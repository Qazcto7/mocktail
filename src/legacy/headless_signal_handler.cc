#include <dlfcn.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "compat/bionic_abi_exports.h"
#include "legacy/headless_signal_helpers.h"
#include "legacy/headless_signal_state.h"
#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/rbxm_diagnostics.h"
#include "legacy/runtime_environment.h"
#include "legacy/stage6_offsets.h"
#include "legacy/stage6_rbxm_fallbacks.h"
#include "legacy/stage6_runtime.h"
#include "legacy/stage6_signal_recovery.h"
#include "legacy/stage6_start_lua_fallbacks.h"

namespace mocktail::legacy::internal {

bool TryHandleStage6GlQueueTraceTrap(int signo, uintptr_t libroblox_base,
                                     uintptr_t libroblox_offset,
                                     ucontext_t* ucontext) {
  if (signo != SIGTRAP || g_current_stage < 6 || libroblox_base == 0 ||
      ucontext == nullptr ||
      (!IsEnabled("MOCKTAIL_TRACE_STAGE6_GL_QUEUE") &&
       !IsEnabled("MOCKTAIL_PATCH_STAGE6_GL_POLL_SYNTHETIC_RETURN_FALSE") &&
       !IsEnabled(
           "MOCKTAIL_PATCH_STAGE6_GL_QUEUE_DRAIN_SYNTHETIC_RETURN_FALSE"))) {
    return false;
  }

  auto emulate_push_rbp = [&](uintptr_t next_offset) -> bool {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rsp < sizeof(uintptr_t) ||
        !IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      return false;
    }
    *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    ucontext->uc_mcontext.gregs[REG_RSP] =
        static_cast<greg_t>(rsp - sizeof(uintptr_t));
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  };

  auto emulate_ret_false = [&]() -> bool {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (!IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      return false;
    }
    const uintptr_t return_address = ReadPointerIfReadable(rsp);
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RSP] =
        static_cast<greg_t>(rsp + sizeof(uintptr_t));
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(return_address);
    return true;
  };

  if (libroblox_offset == kStage6StartLuaResolverSchedulerEntryOffset ||
      libroblox_offset == kStage6StartLuaResolverSchedulerEntryOffset + 1) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t global_scratch_state =
        reinterpret_cast<uintptr_t>(g_stage6_gl_global_scratch) + 0x1000;
    const uintptr_t tls_scratch_state =
        reinterpret_cast<uintptr_t>(g_stage6_gl_scratch) + 0x1000;
    const bool synthetic_state =
        state == global_scratch_state || state == tls_scratch_state ||
        (ReadPointerIfReadable(state + 0x68) == state &&
         ReadPointerIfReadable(state + 0x70) == state &&
         ReadPointerIfReadable(state + 0x08) != 0);
    static volatile sig_atomic_t poll_logs = 0;
    if (IsEnabled("MOCKTAIL_TRACE_STAGE6_GL_QUEUE") && poll_logs < 64) {
      char msg[820];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 GL poll enter off=0x%lx state=%p synthetic=%d "
          "fields{8=%p 20=%p 68=%p 70=%p d260=%p d268=%p d270=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(state), synthetic_state ? 1 : 0,
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0xd260)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0xd268)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0xd270)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++poll_logs;
    }
    if (synthetic_state &&
        IsEnabled("MOCKTAIL_PATCH_STAGE6_GL_POLL_SYNTHETIC_RETURN_FALSE")) {
      return emulate_ret_false();
    }
    return emulate_push_rbp(kStage6StartLuaResolverSchedulerEntryOffset + 1);
  }

  if (libroblox_offset == kStage6GlQueuePopHelperOffset ||
      libroblox_offset == kStage6GlQueuePopHelperOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t token =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    static volatile sig_atomic_t pop_logs = 0;
    if (pop_logs < 64) {
      const uintptr_t lanes = ReadPointerIfReadable(queue + 0x08);
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 GL queue pop enter off=0x%lx queue=%p token=0x%lx "
          "lanes=%p queue_fields{8=%p 10=%p 18=%p 20=%p 60=%p 68=%p 70=%p} "
          "lane0{%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue), static_cast<unsigned long>(token),
          reinterpret_cast<void*>(lanes),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lanes + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lanes + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lanes + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lanes + 0x40)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++pop_logs;
    }
    return emulate_push_rbp(kStage6GlQueuePopHelperOffset + 1);
  }

  if (libroblox_offset == kStage6GlWaitHelperOffset ||
      libroblox_offset == kStage6GlWaitHelperOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t generation =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t timeout =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    static volatile sig_atomic_t wait_logs = 0;
    if (wait_logs < 64) {
      const uintptr_t descriptor = ReadPointerIfReadable(owner + 0x70);
      const uintptr_t queue = ReadPointerIfReadable(owner + 0x68);
      char msg[1180];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 GL wait enter off=0x%lx owner=%p generation=0x%lx "
          "timeout=0x%lx owner_fields{8=%p 20=%p 68=%p 70=%p} "
          "descriptor=%p desc_fields{8=%p 10=%p 18=%p 20=%p 28=%p} "
          "queue_fields{8=%p 68=%p 70=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(owner),
          static_cast<unsigned long>(generation),
          static_cast<unsigned long>(timeout),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x20)),
          reinterpret_cast<void*>(queue), reinterpret_cast<void*>(descriptor),
          reinterpret_cast<void*>(descriptor),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x70)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++wait_logs;
    }
    return emulate_push_rbp(kStage6GlWaitHelperOffset + 1);
  }

  if (libroblox_offset == kStage6GlQueueTransferHelperOffset ||
      libroblox_offset == kStage6GlQueueTransferHelperOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t flag =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    static volatile sig_atomic_t transfer_logs = 0;
    if (transfer_logs < 64) {
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 GL queue transfer enter off=0x%lx queue=%p task=%p "
          "flag=0x%lx context=%p lanes=%p queue_callbacks{10=%p 18=%p 20=%p} "
          "task_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 40=%p 48=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue), reinterpret_cast<void*>(task),
          static_cast<unsigned long>(flag), reinterpret_cast<void*>(context),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x40)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++transfer_logs;
    }
    return emulate_push_rbp(kStage6GlQueueTransferHelperOffset + 1);
  }

  if (libroblox_offset == kStage6GlQueueDrainHelperOffset ||
      libroblox_offset == kStage6GlQueueDrainHelperOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t item =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t callback =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t global_scratch_queue =
        reinterpret_cast<uintptr_t>(g_stage6_gl_global_scratch) + 0x1800;
    const uintptr_t tls_scratch_queue =
        reinterpret_cast<uintptr_t>(g_stage6_gl_scratch) + 0x1800;
    const bool synthetic_item =
        item == global_scratch_queue || item == tls_scratch_queue;
    static volatile sig_atomic_t drain_logs = 0;
    if (IsEnabled("MOCKTAIL_TRACE_STAGE6_GL_QUEUE") && drain_logs < 64) {
      char msg[760];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 GL queue drain enter off=0x%lx owner=%p item=%p "
          "callback=%p owner_fields{68=%p 70=%p} item_fields{0=%p 8=%p "
          "20=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(owner), reinterpret_cast<void*>(item),
          reinterpret_cast<void*>(callback),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(item + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(item + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(item + 0x20)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++drain_logs;
    }
    if (synthetic_item &&
        IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_GL_QUEUE_DRAIN_SYNTHETIC_RETURN_FALSE")) {
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6GlQueueDrainHelperOffset + 0x20e);
      return true;
    }
    return emulate_push_rbp(kStage6GlQueueDrainHelperOffset + 1);
  }

  return false;
}

bool TryHandleStage6FmodTraceTrap(int signo, uintptr_t libroblox_base,
                                  uintptr_t libroblox_offset,
                                  ucontext_t* ucontext) {
  if (signo != SIGTRAP || g_current_stage < 6 || libroblox_base == 0 ||
      ucontext == nullptr ||
      (!IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_ERRORS") &&
       !IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") &&
       !IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_CREATE_GROUP") &&
       !IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_INIT_FAILURE_AS_SUCCESS"))) {
    return false;
  }

  if (IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_CREATE_GROUP") &&
      (libroblox_offset == kStage6FmodCreateChannelGroupWrapperReturnOffset ||
       libroblox_offset ==
           kStage6FmodCreateChannelGroupWrapperReturnOffset + 1)) {
    const uint32_t result =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t return_address =
        ReadPointerIfReadable(rbp + sizeof(uintptr_t));
    const uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    const uintptr_t system =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t name =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t output_value = ReadPointerIfReadable(output);
    const unsigned int initialized =
        IsReadableMemoryRange(system + 0x8, 1)
            ? *reinterpret_cast<unsigned char*>(system + 0x8)
            : 0xffu;
    const uintptr_t mutex = ReadPointerIfReadable(system + 0x115b8);
    char name_preview[96];
    ReadCStringPreview(name, name_preview, sizeof(name_preview));

    char msg[720];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 FMOD createChannelGroup wrapper return result=0x%x "
        "return_off=0x%lx system=%p name=%p \"%s\" output=%p "
        "output_value=%p fields{initialized=0x%x mutex=%p}\n",
        result, static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(system), reinterpret_cast<void*>(name),
        name_preview, reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(output_value), initialized,
        reinterpret_cast<void*>(mutex));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    auto& rax = ucontext->uc_mcontext.gregs[REG_RAX];
    rax = static_cast<greg_t>(
        (static_cast<uintptr_t>(rax) & ~uintptr_t{0xffffffff}) | result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6FmodCreateChannelGroupWrapperReturnOffset + 3);
    return true;
  }

  if (IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_CREATE_GROUP") &&
      (libroblox_offset == kStage6FmodCreateChannelGroupReturnOffset ||
       libroblox_offset == kStage6FmodCreateChannelGroupReturnOffset + 1)) {
    const uint32_t result =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t return_address =
        ReadPointerIfReadable(rbp + sizeof(uintptr_t));
    const uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    const uintptr_t system =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    const uintptr_t group =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t output_value = ReadPointerIfReadable(output);
    const uintptr_t name = ReadPointerIfReadable(rbp - 0x168);
    const uintptr_t group_object = ReadPointerIfReadable(rbp - 0x158);
    const unsigned int initialized =
        IsReadableMemoryRange(system + 0x8, 1)
            ? *reinterpret_cast<unsigned char*>(system + 0x8)
            : 0xffu;
    char name_preview[96];
    ReadCStringPreview(name, name_preview, sizeof(name_preview));

    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 FMOD createChannelGroup return result=0x%x "
        "return_off=0x%lx system=%p group=%p group_object=%p name=%p "
        "\"%s\" output=%p output_value=%p initialized=0x%x\n",
        result, static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(system), reinterpret_cast<void*>(group),
        reinterpret_cast<void*>(group_object), reinterpret_cast<void*>(name),
        name_preview, reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(output_value), initialized);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    auto& rax = ucontext->uc_mcontext.gregs[REG_RAX];
    rax = static_cast<greg_t>(
        (static_cast<uintptr_t>(rax) & ~uintptr_t{0xffffffff}) | result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6FmodCreateChannelGroupReturnOffset + 3);
    return true;
  }

  if (IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") &&
      (libroblox_offset == kStage6FmodSystemCreateReturnOffset ||
       libroblox_offset == kStage6FmodSystemCreateReturnOffset + 1)) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t system = ReadPointerIfReadable(rbp - 0xc8);
    const uint32_t result =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RAX]);

    char msg[320];
    int len = snprintf(msg, sizeof(msg),
                       "  [trace] Stage6 FMOD System_Create return result=0x%x "
                       "system=%p rbp=%p\n",
                       result, reinterpret_cast<void*>(system),
                       reinterpret_cast<void*>(rbp));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    auto& r14 = ucontext->uc_mcontext.gregs[REG_R14];
    r14 = static_cast<greg_t>(
        (static_cast<uintptr_t>(r14) & ~uintptr_t{0xffffffff}) | result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6FmodSystemCreateReturnOffset + 3);
    return true;
  }

  if (IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") &&
      (libroblox_offset == kStage6FmodSystemInitOffset ||
       libroblox_offset == kStage6FmodSystemInitOffset + 1)) {
    const uintptr_t system =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uint32_t mode =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uint32_t flags =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t extra =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t return_address = ReadPointerIfReadable(rsp);
    const uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    const uintptr_t mutex = ReadPointerIfReadable(system + 0x115b8);
    const uintptr_t init_thread = ReadPointerIfReadable(system + 0x11900);
    const unsigned int thread_flag =
        IsReadableMemoryRange(system + 0x11908, 1)
            ? *reinterpret_cast<unsigned char*>(system + 0x11908)
            : 0xffu;
    const uintptr_t driver = ReadPointerIfReadable(system + 0x11850);
    const uint32_t output_type = ReadU32IfReadable(system + 0x11858);

    char msg[640];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 FMOD System::init entry system=%p mode=%u "
        "flags=%u extra=%p return_off=0x%lx fields{mutex=%p "
        "init_thread=%p thread_flag=0x%x driver=%p output_type=0x%x}\n",
        reinterpret_cast<void*>(system), mode, flags,
        reinterpret_cast<void*>(extra),
        static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(mutex), reinterpret_cast<void*>(init_thread),
        thread_flag, reinterpret_cast<void*>(driver), output_type);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (rsp < sizeof(uintptr_t) ||
        !IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      return false;
    }
    *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    ucontext->uc_mcontext.gregs[REG_RSP] =
        static_cast<greg_t>(rsp - sizeof(uintptr_t));
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6FmodSystemInitOffset + 1);
    return true;
  }

  if ((IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") ||
       IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_INIT_FAILURE_AS_SUCCESS")) &&
      (libroblox_offset == kStage6FmodSystemInitFunctionReturnOffset ||
       libroblox_offset == kStage6FmodSystemInitFunctionReturnOffset + 1)) {
    uint32_t result =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t return_address =
        ReadPointerIfReadable(rbp + sizeof(uintptr_t));
    const uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    const uintptr_t system =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t mutex = ReadPointerIfReadable(system + 0x115b8);
    const uintptr_t init_thread = ReadPointerIfReadable(system + 0x11900);
    const unsigned int thread_flag =
        IsReadableMemoryRange(system + 0x11908, 1)
            ? *reinterpret_cast<unsigned char*>(system + 0x11908)
            : 0xffu;
    const uintptr_t driver = ReadPointerIfReadable(system + 0x11850);
    const uint32_t output_type = ReadU32IfReadable(system + 0x11858);

    char msg[560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 FMOD System::init function return result=0x%x "
        "return_off=0x%lx system=%p fields{mutex=%p init_thread=%p "
        "thread_flag=0x%x driver=%p output_type=0x%x}\n",
        result, static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(system), reinterpret_cast<void*>(mutex),
        reinterpret_cast<void*>(init_thread), thread_flag,
        reinterpret_cast<void*>(driver), output_type);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (result != 0 &&
        return_offset == kStage6FmodNativeAudioDeviceRetryReturnOffset &&
        IsEnabled("MOCKTAIL_PATCH_STAGE6_FMOD_INIT_FAILURE_AS_SUCCESS") &&
        IsReadableMemoryRange(system + 0x8, 1)) {
      *reinterpret_cast<unsigned char*>(system + 0x8) = 1;
      result = 0;
      const char patch_msg[] =
          "  [patch] Stage6 FMOD retry init failure marked initialized\n";
      write(2, patch_msg, sizeof(patch_msg) - 1);
    }

    auto& rax = ucontext->uc_mcontext.gregs[REG_RAX];
    rax = static_cast<greg_t>(
        (static_cast<uintptr_t>(rax) & ~uintptr_t{0xffffffff}) | result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6FmodSystemInitFunctionReturnOffset + 3);
    return true;
  }

  if (IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_INIT") &&
      (libroblox_offset == kStage6FmodSystemInitReturnOffset ||
       libroblox_offset == kStage6FmodSystemInitReturnOffset + 1)) {
    const uint32_t result =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t manager =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t system = ReadPointerIfReadable(manager + 0x98);
    const uintptr_t mutex = ReadPointerIfReadable(system + 0x115b8);
    const uintptr_t init_thread = ReadPointerIfReadable(system + 0x11900);
    const unsigned int thread_flag =
        IsReadableMemoryRange(system + 0x11908, 1)
            ? *reinterpret_cast<unsigned char*>(system + 0x11908)
            : 0xffu;

    char msg[480];
    int len = snprintf(msg, sizeof(msg),
                       "  [trace] Stage6 FMOD System::init return result=0x%x "
                       "manager=%p system=%p fields{mutex=%p init_thread=%p "
                       "thread_flag=0x%x}\n",
                       result, reinterpret_cast<void*>(manager),
                       reinterpret_cast<void*>(system),
                       reinterpret_cast<void*>(mutex),
                       reinterpret_cast<void*>(init_thread), thread_flag);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    auto& r13 = ucontext->uc_mcontext.gregs[REG_R13];
    r13 = static_cast<greg_t>(
        (static_cast<uintptr_t>(r13) & ~uintptr_t{0xffffffff}) | result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6FmodSystemInitReturnOffset + 3);
    return true;
  }

  if (!IsEnabled("MOCKTAIL_TRACE_STAGE6_FMOD_ERRORS") ||
      (libroblox_offset != kStage6FmodLogHelperOffset &&
       libroblox_offset != kStage6FmodLogHelperOffset + 1)) {
    return false;
  }

  const uintptr_t function_name =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
  const uintptr_t error_string =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
  const uintptr_t rsp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
  const uintptr_t return_address = ReadPointerIfReadable(rsp);
  const uintptr_t return_offset =
      return_address >= libroblox_base ? return_address - libroblox_base : 0;

  char function_preview[96];
  char error_preview[192];
  ReadCStringPreview(function_name, function_preview, sizeof(function_preview));
  ReadCStringPreview(error_string, error_preview, sizeof(error_preview));

  char msg[760];
  int len = snprintf(
      msg, sizeof(msg),
      "  [trace] Stage6 FMOD log helper function=%p \"%s\" error=%p \"%s\" "
      "return_off=0x%lx rdx=%p rcx=%p r8=%p\n",
      reinterpret_cast<void*>(function_name), function_preview,
      reinterpret_cast<void*>(error_string), error_preview,
      static_cast<unsigned long>(return_offset),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8]));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }

  if (rsp < sizeof(uintptr_t) ||
      !IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
    return false;
  }
  *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
  ucontext->uc_mcontext.gregs[REG_RSP] =
      static_cast<greg_t>(rsp - sizeof(uintptr_t));
  ucontext->uc_mcontext.gregs[REG_RIP] =
      static_cast<greg_t>(libroblox_base + kStage6FmodLogHelperOffset + 1);
  return true;
}

void HeadlessSegvHandler(int signo, siginfo_t* info, void* context) {
#if defined(__x86_64__)
  auto* ucontext = static_cast<ucontext_t*>(context);
  auto* instruction =
      reinterpret_cast<unsigned char*>(ucontext->uc_mcontext.gregs[REG_RIP]);
  const uintptr_t instruction_address =
      reinterpret_cast<uintptr_t>(instruction);
  unsigned char unreadable_instruction[16] = {};
  const bool instruction_readable =
      g_libroblox_base != 0 &&
      instruction_address >= static_cast<uintptr_t>(g_libroblox_base) &&
      instruction_address + 16 >= instruction_address &&
      instruction_address + 16 <
          static_cast<uintptr_t>(g_libroblox_base) + 0x08000000;
  bool is_zero_page_instruction = false;
  if (instruction_readable) {
    is_zero_page_instruction = true;
    for (int i = 0; i < 16; ++i) {
      if (instruction[i] != 0x00) {
        is_zero_page_instruction = false;
        break;
      }
    }
  }

  Dl_info dlinfo;
  const char* symbol_name = "(unknown)";
  const char* module_name = "(unknown)";
  const void* symbol_addr = nullptr;
  if (dladdr(instruction, &dlinfo) != 0) {
    if (dlinfo.dli_sname != nullptr && dlinfo.dli_sname[0] != '\0') {
      symbol_name = dlinfo.dli_sname;
    }
    if (dlinfo.dli_fname != nullptr && dlinfo.dli_fname[0] != '\0') {
      module_name = dlinfo.dli_fname;
    }
    symbol_addr = dlinfo.dli_saddr;
  }

  if (!instruction_readable) {
    instruction = unreadable_instruction;
  }

  if (g_libroblox_ctor_recovery_in_progress != 0) {
    g_libroblox_ctor_recovery_in_progress = 0;
    g_libroblox_ctor_recovered_signo = signo;
    g_libroblox_ctor_recovered_rip =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
    g_libroblox_ctor_recovered_si_addr =
        reinterpret_cast<uintptr_t>(info != nullptr ? info->si_addr : nullptr);
    siglongjmp(g_libroblox_ctor_jmp_buf, 1);
  }

  if (g_current_stage >= 6 && ucontext != nullptr) {
    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    uintptr_t return_address = stack != nullptr ? stack[0] : 0;
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    if (base == 0) {
      base = static_cast<uintptr_t>(g_libroblox_base);
    }
    uintptr_t return_offset =
        (base != 0 && return_address >= base) ? return_address - base : 0;
    uintptr_t key_address =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    bool key_is_static_libroblox_data =
        base != 0 && key_address >= base &&
        key_address + sizeof(uint64_t) * 4 >= key_address &&
        key_address + sizeof(uint64_t) * 4 <= base + 0x9000000;
    if (return_offset == 0x2c18f1e && key_is_static_libroblox_data) {
      const auto* key = reinterpret_cast<const uint64_t*>(key_address);
      uint64_t size = key[0];
      uint64_t align = key[1];
      uint64_t initializer = key[3];
      uintptr_t value =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
      if (value == 0) {
        value = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
      }
      bool valid_zero_initializer = initializer == 0 && size > 0 &&
                                    size <= 0x10000 && align > 0 &&
                                    (align & (align - 1)) == 0;
      if (valid_zero_initializer) {
        auto* bytes = reinterpret_cast<volatile unsigned char*>(value);
        for (uint64_t i = 0; i < size; ++i) {
          bytes[i] = 0;
        }
        char msg[480];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] completed early emutls zero initializer manually "
            "key_off=0x%lx size=0x%llx align=0x%llx value=%p return=%p\n",
            static_cast<unsigned long>(key_address - base),
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(align),
            reinterpret_cast<void*>(value),
            reinterpret_cast<void*>(return_address));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
        return;
      }
    }
  }

  uintptr_t rax = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
  if (g_current_stage >= 5 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    if (TryHandleStage5LowAddressAtomic(ucontext, instruction)) {
      return;
    }
  }

  if (g_current_stage >= 6 && info && instruction_readable) {
    const uintptr_t fault_address = reinterpret_cast<uintptr_t>(info->si_addr);
    const bool is_libc_vector_store =
        strstr(module_name, "libc.so") != nullptr &&
        ((instruction[0] == 0xc5 && instruction[2] == 0x7f) ||
         (instruction[0] == 0xc4 && instruction[3] == 0x7f));
    const uintptr_t rdi =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t rdx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t rcx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t r8 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R8]);
    bool redirect_rdi = false;
    bool redirect_rdx = false;
    bool redirect_rcx = false;
    bool redirect_r8 = false;
    if (instruction[0] == 0xc5 && instruction[2] == 0x7f) {
      const unsigned char modrm = instruction[3];
      const unsigned char rm_form = modrm & 0xc7;
      if (rm_form == 0x07 || rm_form == 0x47) {
        redirect_rdi = true;
      } else if ((modrm & 0xc7) == 0x44 && instruction[4] == 0x17) {
        // SIB: base=rdi, index=rdx.  RDX is the copy size here, not a base.
        redirect_rdi = true;
      } else if (rm_form == 0x02 || rm_form == 0x42) {
        redirect_rdx = true;
      } else if (rm_form == 0x01) {
        redirect_rcx = true;
      }
    } else if (instruction[0] == 0xc4 && instruction[3] == 0x7f &&
               instruction[4] == 0x00) {
      redirect_r8 = true;
    }
    const auto can_redirect_copy_reg = [](uintptr_t value) {
      return value < kStage5FallbackScratchSize - 0x200;
    };
    if (is_libc_vector_store && ((redirect_rdi && can_redirect_copy_reg(rdi)) ||
                                 (redirect_rdx && can_redirect_copy_reg(rdx)) ||
                                 (redirect_rcx && can_redirect_copy_reg(rcx)) ||
                                 (redirect_r8 && can_redirect_copy_reg(r8)))) {
      const uintptr_t scratch_base =
          reinterpret_cast<uintptr_t>(g_stage5_fallback_region);
      auto redirect_low_copy_reg = [scratch_base](greg_t* reg) {
        const uintptr_t value = static_cast<uintptr_t>(*reg);
        if (value < kStage5FallbackScratchSize - 0x200) {
          *reg = static_cast<greg_t>(scratch_base + value);
        }
      };
      if (g_stage6_low_memcpy_redirect_logs < 8) {
        char msg[360];
        int len =
            snprintf(msg, sizeof(msg),
                     "  [patch] redirected Stage6 low-address libc vector copy "
                     "fault=%p rdi=%p rdx=%p rcx=%p r8=%p scratch=%p\n",
                     reinterpret_cast<void*>(fault_address),
                     reinterpret_cast<void*>(rdi), reinterpret_cast<void*>(rdx),
                     reinterpret_cast<void*>(rcx), reinterpret_cast<void*>(r8),
                     reinterpret_cast<void*>(g_stage5_fallback_region));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_low_memcpy_redirect_logs;
      }
      ++g_skipped_headless_null_writes;
      if (redirect_rdi) {
        redirect_low_copy_reg(&ucontext->uc_mcontext.gregs[REG_RDI]);
      }
      if (redirect_rdx) {
        redirect_low_copy_reg(&ucontext->uc_mcontext.gregs[REG_RDX]);
      }
      if (redirect_rcx) {
        redirect_low_copy_reg(&ucontext->uc_mcontext.gregs[REG_RCX]);
      }
      if (redirect_r8) {
        redirect_low_copy_reg(&ucontext->uc_mcontext.gregs[REG_R8]);
      }
      ucontext->uc_mcontext.gregs[REG_RAX] =
          reinterpret_cast<greg_t>(g_stage5_fallback_region);
      return;
    }
  }

  const uintptr_t libroblox_offset_for_mid_instruction =
      (g_libroblox_base != 0 && instruction_address >= g_libroblox_base)
          ? instruction_address - static_cast<uintptr_t>(g_libroblox_base)
          : 0;
  if (g_current_stage >= 6 &&
      libroblox_offset_for_mid_instruction >=
          kStage6MidInstructionMovabsOffset &&
      libroblox_offset_for_mid_instruction <=
          kStage6MidInstructionMovabsEndOffset) {
    if (g_skipped_headless_null_writes < 64) {
      char msg[300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] corrected Stage6 mid-instruction movabs "
          "rip=%p off=0x%lx\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset_for_mid_instruction));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(static_cast<uintptr_t>(g_libroblox_base) +
                            kStage6MidInstructionMovabsStartOffset);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset_for_mid_instruction ==
          kStage6MidInstructionMovabsOffset &&
      instruction_address > static_cast<uintptr_t>(g_libroblox_base) + 4 &&
      instruction[-4] == 0x48 && instruction[-3] == 0xb9 &&
      instruction[0] == 0xff && instruction[1] == 0xff &&
      instruction[2] == 0xff && instruction[3] == 0xff &&
      instruction[4] == 0xff && instruction[5] == 0x7f) {
    if (g_skipped_headless_null_writes < 64) {
      char msg[300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] corrected Stage6 mid-instruction movabs "
          "rip=%p off=0x%lx\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset_for_mid_instruction));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] -= 4;
    return;
  }

  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset_for_mid_instruction ==
          kStage6MidInstructionEpilogueOffset &&
      instruction_address > static_cast<uintptr_t>(g_libroblox_base) &&
      instruction[-1] == 0x48 && instruction[0] == 0x83 &&
      instruction[1] == 0xc4 && instruction[2] == 0x28) {
    if (g_skipped_headless_null_writes < 64) {
      char msg[300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] corrected Stage6 mid-instruction epilogue "
          "rip=%p off=0x%lx\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset_for_mid_instruction));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] -= 1;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x3c && instruction[3] == 0x08) {
    if (g_stage6_segment_read_logs < 12) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 missing segment-table entry read "
          "rip=%p rax=%p rcx=%p rsi=%p si_addr=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          info->si_addr);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_segment_read_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x3c && instruction[3] == 0x10) {
    const char msg[] =
        "  [patch] skipped Stage6 low-address allocator metadata read\n";
    write(2, msg, sizeof(msg) - 1);
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x49 && instruction[1] == 0x8b &&
      instruction[2] == 0x40 && instruction[3] == 0x08) {
    const char msg[] = "  [patch] skipped Stage6 low-address hash node read\n";
    write(2, msg, sizeof(msg) - 1);
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x8b && instruction[1] == 0x40 &&
      instruction[2] == 0x08) {
    const char msg[] =
        "  [patch] skipped Stage6 low-address hash node read (mid-rip)\n";
    write(2, msg, sizeof(msg) - 1);
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0xff && instruction[1] == 0x90) {
    int32_t call_offset = 0;
    std::memcpy(&call_offset, instruction + 2, sizeof(call_offset));
    uintptr_t rax =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    if (rax == 0 && call_offset >= 0 && call_offset <= 0x800) {
      uintptr_t env_functions = g_stage6_jni_functions;
      if (env_functions >= kStage5LowAddressThreshold) {
        if (g_restored_stage6_jni_table_logs < 8) {
          char msg[320];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] restored Stage6 JNI table for virtual call rip=%p "
              "disp=0x%x table=%p\n",
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
              call_offset, reinterpret_cast<void*>(env_functions));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_restored_stage6_jni_table_logs;
        }
        ucontext->uc_mcontext.gregs[REG_RAX] =
            static_cast<greg_t>(env_functions);
        return;
      }
    }
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] skipped Stage6 null virtual call rip=%p off=0x%lx "
        "si_addr=%p "
        "rax=%p rdi=%p rsi=%p rdx=%p rcx=%p\n",
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
        dlinfo.dli_fbase ? static_cast<unsigned long>(
                               reinterpret_cast<uintptr_t>(instruction) -
                               reinterpret_cast<uintptr_t>(dlinfo.dli_fbase))
                         : 0ul,
        info->si_addr,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 6;
    return;
  }

  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x41 && instruction[1] == 0xff &&
      instruction[2] == 0x90) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] skipped Stage6 null R8 virtual call rip=%p off=0x%lx "
        "si_addr=%p "
        "rax=%p r8=%p rdi=%p rsi=%p rdx=%p\n",
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
        dlinfo.dli_fbase ? static_cast<unsigned long>(
                               reinterpret_cast<uintptr_t>(instruction) -
                               reinterpret_cast<uintptr_t>(dlinfo.dli_fbase))
                         : 0ul,
        info->si_addr,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 7;
    return;
  }

  uintptr_t libroblox_base = 0;
  uintptr_t libroblox_offset = 0;
  if (g_libroblox_base != 0 &&
      instruction_address >= static_cast<uintptr_t>(g_libroblox_base) &&
      instruction_address <
          static_cast<uintptr_t>(g_libroblox_base) + 0x08000000) {
    libroblox_base = g_libroblox_base;
    libroblox_offset = instruction_address - g_libroblox_base;
  } else if (dlinfo.dli_fbase) {
    libroblox_base = reinterpret_cast<uintptr_t>(dlinfo.dli_fbase);
    libroblox_offset = instruction_address - libroblox_base;
  }
  if (g_current_stage >= 6 && TryReturnFromStage6ActivityLifecycleNullObserver(
                                  ucontext, libroblox_offset)) {
    const char msg[] =
        "  [patch] globally recovered empty activity-lifecycle observer "
        "dispatch\n";
    write(2, msg, sizeof(msg) - 1);
    return;
  }
  if (TryHandleStage6FmodTraceTrap(signo, libroblox_base, libroblox_offset,
                                   ucontext)) {
    return;
  }
  if (TryHandleStage6GlQueueTraceTrap(signo, libroblox_base, libroblox_offset,
                                      ucontext)) {
    return;
  }
  if (TryHandleStage6StartLuaTraceTrap(signo, libroblox_base, libroblox_offset,
                                       ucontext)) {
    return;
  }
  if (g_current_stage >= 6 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0)) {
    if (TryHandleStage6StartAppZeroStrideDivisor(
            signo, libroblox_base, libroblox_offset, ucontext, instruction,
            instruction_readable) ||
        TryHandleStage6StartAppNullStateObjectRead(
            signo, info, libroblox_base, libroblox_offset, ucontext,
            instruction, instruction_readable) ||
        TryHandleStage6StartLuaObserverListInvalidCursor(
            signo, info, libroblox_base, libroblox_offset, ucontext,
            instruction, instruction_readable)) {
      return;
    }
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartLuaResult20FallbackGlobalSlotReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x30 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_FALLBACK_NULL_GLOBAL_"
                "SLOT")) {
    const uintptr_t target =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    static volatile sig_atomic_t result20_fallback_null_global_logs = 0;
    if (result20_fallback_null_global_logs < 32) {
      char msg[920];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartLua result20 fallback global slot null: "
          "continuing with empty source rip_off=0x%lx rax=%p si_addr=%p "
          "rdi=%p rsi=%p rbx=%p target=%p target228=%p caller_return=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(target),
          reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x228)),
          reinterpret_cast<void*>(ReadPointerIfReadable(
              static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]) +
              sizeof(uintptr_t))));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++result20_fallback_null_global_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RSI] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResult20FallbackGlobalSlotResumeOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6RbxmChildNameStringReadOffset &&
      info->si_addr == nullptr && instruction[0] == 0x0f &&
      instruction[1] == 0xb6 && instruction[2] == 0x08) {
    const uintptr_t child =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t children_cursor =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    const uintptr_t remaining =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    const uintptr_t target_name =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t target_length =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    char target_preview[96];
    ReadRawStringPreview(target_name, std::min<uintptr_t>(target_length, 80),
                         target_preview, sizeof(target_preview));
    static volatile sig_atomic_t rbxm_child_name_null_logs = 0;
    if (rbxm_child_name_null_logs < 64) {
      char msg[960];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 RBXM child-name null string "
          "rip_off=0x%lx child=%p name_slot=%p cursor=%p remaining=0x%lx "
          "target=\"%s\" target_len=0x%lx fields{78=%p b0=%p b8=%p c0=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(child),
          reinterpret_cast<void*>(ReadPointerIfReadable(child + 0xb0)),
          reinterpret_cast<void*>(children_cursor),
          static_cast<unsigned long>(remaining), target_preview,
          static_cast<unsigned long>(target_length),
          reinterpret_cast<void*>(ReadPointerIfReadable(child + 0x78)),
          reinterpret_cast<void*>(ReadPointerIfReadable(child + 0xb0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(child + 0xb8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(child + 0xc0)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_child_name_null_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + 0x65bc121);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      (libroblox_offset == kStage6StartAppInitialInstanceNameStringReadOffset ||
       libroblox_offset == kStage6StartAppPeerInstanceNameStringReadOffset ||
       libroblox_offset == kStage6StartAppDeepInstanceNameStringReadOffset ||
       libroblox_offset ==
           kStage6StartAppPostHashInstanceNameStringReadOffset ||
       libroblox_offset == kStage6StartAppInstanceNameStringReadOffset ||
       libroblox_offset ==
           kStage6StartAppFallbackInstanceNameStringReadOffset ||
       libroblox_offset ==
           kStage6StartAppSecondFallbackInstanceNameStringReadOffset ||
       libroblox_offset ==
           kStage6StartAppThirdFallbackInstanceNameStringReadOffset) &&
      info->si_addr == nullptr && instruction[0] == 0x0f &&
      instruction[1] == 0xb6 && instruction[2] == 0x08 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t skip_offset = kStage6StartAppFallbackInstanceNameSkipOffset;
    if (libroblox_offset ==
        kStage6StartAppInitialInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppInitialInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppPeerInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppPeerInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppDeepInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppDeepInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppPostHashInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppPostHashInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppSecondFallbackInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppSecondFallbackInstanceNameSkipOffset;
    } else if (libroblox_offset ==
               kStage6StartAppThirdFallbackInstanceNameStringReadOffset) {
      skip_offset = kStage6StartAppThirdFallbackInstanceNameSkipOffset;
    }
    static volatile sig_atomic_t start_app_instance_name_null_logs = 0;
    if (start_app_instance_name_null_logs < 32) {
      char msg[760];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 StartApp instance-name null string "
          "rip_off=0x%lx object=%p name_slot=%p bridge=%p "
          "fields{60=%p 78=%p b0=%p b8=%p c0=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(object),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0xb0)),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x78)),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0xb0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0xb8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0xc0)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++start_app_instance_name_null_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + skip_offset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 && g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartLuaReverseStringCopyNullDestStoreOffset &&
      instruction[0] == 0x88 && instruction[1] == 0x11 &&
      reinterpret_cast<uintptr_t>(info->si_addr) ==
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]) &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]) <
          kStage5LowAddressThreshold) {
    static volatile sig_atomic_t start_lua_reverse_copy_logs = 0;
    if (start_lua_reverse_copy_logs < 32) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 StartLua reverse-copy null destination "
          "rip_off=0x%lx src=%p dest=%p done_off=0x%lx\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
          static_cast<unsigned long>(
              kStage6StartLuaReverseStringCopyDoneOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++start_lua_reverse_copy_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaReverseStringCopyDoneOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset ==
          kStage6StartAppReverseStringCopyInvalidDestStoreOffset &&
      instruction[0] == 0x88 && instruction[1] == 0x11) {
    const uintptr_t destination =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const bool invalid_destination = destination < kStage5LowAddressThreshold ||
                                     destination >= kMaxCanonicalUserPointer ||
                                     !IsReadableMemoryRange(destination, 1);
    if (invalid_destination) {
      static volatile sig_atomic_t start_app_reverse_copy_logs = 0;
      if (start_app_reverse_copy_logs < 32) {
        char msg[460];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 StartApp reverse-copy invalid "
            "destination rip_off=0x%lx src=%p dest=%p done_off=0x%lx\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
            reinterpret_cast<void*>(destination),
            static_cast<unsigned long>(
                kStage6StartAppReverseStringCopyDoneOffset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++start_app_reverse_copy_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartAppReverseStringCopyDoneOffset);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_init_with_params_recovery_in_progress != 0 ||
       g_start_app_with_params_recovery_in_progress != 0 ||
       g_update_surface_app_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset ==
          kStage6StartLuaDMInvokerReverseStringCopyStoreOffset &&
      instruction[0] == 0x88 && instruction[1] == 0x11) {
    const uintptr_t destination =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const bool invalid_destination = destination < kStage5LowAddressThreshold ||
                                     destination >= kMaxCanonicalUserPointer ||
                                     !IsReadableMemoryRange(destination, 1);
    if (invalid_destination) {
      static volatile sig_atomic_t invoker_reverse_copy_logs = 0;
      if (invoker_reverse_copy_logs < 32) {
        char msg[520];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 StartLuaDM invoker reverse-copy "
            "invalid destination rip_off=0x%lx src=%p dest=%p "
            "done_off=0x%lx\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
            reinterpret_cast<void*>(destination),
            static_cast<unsigned long>(
                kStage6StartLuaDMInvokerReverseStringCopyDoneOffset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++invoker_reverse_copy_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaDMInvokerReverseStringCopyDoneOffset);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppAudioCallbackTableWriteOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x89 &&
      instruction[2] == 0x91 && instruction[3] == 0x60 &&
      instruction[4] == 0x03 && instruction[5] == 0x00 &&
      instruction[6] == 0x00 && ucontext->uc_mcontext.gregs[REG_RCX] == 0) {
    std::memset(g_stage6_audio_callback_table_scratch, 0,
                sizeof(g_stage6_audio_callback_table_scratch));
    if (ShouldLogStage6Repeated(&g_stage6_audio_callback_table_logs)) {
      char msg[360];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp audio callback table null: using scratch "
          "table rip_off=0x%lx table=%p callback=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          static_cast<void*>(g_stage6_audio_callback_table_scratch),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage6_audio_callback_table_scratch);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppNullCallbackOwnerFreeReadOffset &&
      instruction[0] == 0x4d && instruction[1] == 0x8b &&
      instruction[2] == 0xa7 && instruction[3] == 0x80 &&
      instruction[4] == 0x03 && instruction[5] == 0x00 &&
      instruction[6] == 0x00 &&
      TryReturnFromStage6StartAppNullAllocatorFree(ucontext,
                                                   libroblox_offset)) {
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppNullCallbackOwnerReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x9f && instruction[3] == 0x80 &&
      instruction[4] == 0x03 && instruction[5] == 0x00 &&
      instruction[6] == 0x00 && ucontext->uc_mcontext.gregs[REG_RDI] == 0) {
    const uintptr_t requested_size =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    bool arena_wrapped = false;
    uintptr_t total_size = 0;
    const uintptr_t allocation = AllocateStage6StartAppNullAllocatorArena(
        requested_size, &arena_wrapped, &total_size);
    if (ShouldLogStage6Repeated(&g_stage6_start_app_null_callback_owner_logs)) {
      char msg[560];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp null allocator owner: returning "
          "arena allocation rip_off=0x%lx requested=0x%lx allocation=%p "
          "total=0x%lx wrapped=%d return_off=0x%lx\n",
          static_cast<unsigned long>(libroblox_offset),
          static_cast<unsigned long>(requested_size),
          reinterpret_cast<void*>(allocation),
          static_cast<unsigned long>(total_size), arena_wrapped ? 1 : 0,
          static_cast<unsigned long>(
              kStage6StartAppNullCallbackOwnerReturnOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(allocation);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppNullCallbackOwnerReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppNullCallbackOwnerTableWriteOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x89 &&
      instruction[2] == 0x08 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t item_offset =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    if (object >= kStage5LowAddressThreshold && item_offset < 0x100000 &&
        IsReadableMemoryRange(object + 0x1e0, 0x3c0) &&
        EnsureWritablePage(reinterpret_cast<void*>(object + 0x1e8))) {
      auto* table_slot = reinterpret_cast<uintptr_t*>(object + 0x1e8);
      uintptr_t table = ReadPointerIfReadable(object + 0x1e8);
      const uintptr_t old_table = table;
      const uintptr_t required_size = item_offset + 0x230;
      const uint32_t table_count = ReadU32IfReadable(object + 0x1e0);
      uintptr_t requested_size =
          table_count > 0 && table_count < 0x10000
              ? static_cast<uintptr_t>(table_count) * 0x230
              : required_size;
      if (requested_size < required_size) {
        requested_size = required_size;
      }
      uint32_t current_native_size = 0;
      uintptr_t current_payload_size = 0;
      if (table >= kStage5LowAddressThreshold &&
          IsReadableMemoryRange(table - 8, 8)) {
        current_native_size = ReadU32IfReadable(table - 8);
        if (current_native_size > 8) {
          current_payload_size = current_native_size - 8;
        }
      }
      bool arena_wrapped = false;
      uintptr_t total_size = 0;
      bool allocated_table = false;
      if (table < kStage5LowAddressThreshold ||
          current_payload_size < required_size ||
          !IsReadableMemoryRange(table + item_offset + 0x178, 0x10)) {
        table = AllocateStage6StartAppNullAllocatorArena(
            requested_size, &arena_wrapped, &total_size);
        *table_slot = table;
        allocated_table = true;
      }

      const uintptr_t list_head = object + 0x598;
      uintptr_t list_next = ReadPointerIfReadable(list_head);
      bool seeded_list_head = false;
      if (list_next < kStage5LowAddressThreshold &&
          IsReadableMemoryRange(list_head, 0x10) &&
          EnsureWritablePage(reinterpret_cast<void*>(list_head))) {
        *reinterpret_cast<uintptr_t*>(list_head) = list_head;
        *reinterpret_cast<uintptr_t*>(list_head + 0x08) = list_head;
        list_next = list_head;
        seeded_list_head = true;
      }

      if (ShouldLogStage6Repeated(
              &g_stage6_start_app_null_callback_owner_table_logs)) {
        char msg[760];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] Stage6 StartApp null allocator owner table: "
            "restored rip_off=0x%lx object=%p item_offset=0x%lx "
            "old_table=%p table=%p allocated=%d requested=0x%lx "
            "required=0x%lx total=0x%lx wrapped=%d count=%u "
            "old_payload=0x%lx list_next=%p seeded_list=%d\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(object),
            static_cast<unsigned long>(item_offset),
            reinterpret_cast<void*>(old_table), reinterpret_cast<void*>(table),
            allocated_table ? 1 : 0, static_cast<unsigned long>(requested_size),
            static_cast<unsigned long>(required_size),
            static_cast<unsigned long>(total_size), arena_wrapped ? 1 : 0,
            table_count, static_cast<unsigned long>(current_payload_size),
            reinterpret_cast<void*>(list_next), seeded_list_head ? 1 : 0);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(table);
      ucontext->uc_mcontext.gregs[REG_RCX] = static_cast<greg_t>(list_next);
      ucontext->uc_mcontext.gregs[REG_RAX] =
          static_cast<greg_t>(table + item_offset + 0x178);
      return;
    }
  }
  if (signo == SIGTRAP && g_current_stage >= 6 && libroblox_base != 0 &&
      libroblox_offset ==
          kStage6DataModelPatchNoVerifiedPatchTrapResumeOffset) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    uintptr_t return_address = ReadPointerIfReadable(rsp);
    uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    bool return_from_frame = false;
    if (return_offset != 0x2464a6e && IsReadableMemoryRange(rbp, 0x18)) {
      return_address = ReadPointerIfReadable(rbp + 0x08);
      return_offset = return_address >= libroblox_base
                          ? return_address - libroblox_base
                          : 0;
      return_from_frame = true;
    }
    if (return_offset == 0x2464a6e) {
      const uintptr_t caller_rbp =
          return_from_frame ? ReadPointerIfReadable(rbp) : rbp;
      const uintptr_t loaded_patch =
          IsReadableMemoryRange(caller_rbp - 0x548, sizeof(uintptr_t))
              ? ReadPointerIfReadable(caller_rbp - 0x548)
              : 0;
      const uintptr_t empty_result =
          IsReadableMemoryRange(caller_rbp - 0x5e8, sizeof(uintptr_t))
              ? ReadPointerIfReadable(caller_rbp - 0x5e8)
              : 0;
      const bool use_empty_result_path =
          loaded_patch < kStage5LowAddressThreshold &&
          IsReadableMemoryRange(empty_result, 0x20);
      const uintptr_t resume_address =
          use_empty_result_path
              ? libroblox_base +
                    kStage6DataModelPatchNoVerifiedPatchEmptyResultOffset
              : return_address;
      if (use_empty_result_path) {
        std::memset(reinterpret_cast<void*>(empty_result), 0, 0x20);
      }
      char msg[480];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] bypassed Stage6 DataModelPatch no-verified-patch "
          "trap rip_off=0x%lx return_off=0x%lx source=%s rdi=%p rax=%p "
          "loaded_patch=%p empty_result=%p empty_path=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          static_cast<unsigned long>(return_offset),
          return_from_frame ? "frame" : "stack",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(loaded_patch),
          reinterpret_cast<void*>(empty_result), use_empty_result_path ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(resume_address);
      if (return_from_frame) {
        ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(
            use_empty_result_path ? empty_result
                                  : ReadPointerIfReadable(rbp - 0x08));
        ucontext->uc_mcontext.gregs[REG_RBX] =
            static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x10));
        ucontext->uc_mcontext.gregs[REG_RBP] =
            static_cast<greg_t>(ReadPointerIfReadable(rbp));
        ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(rbp + 0x10);
      } else {
        ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
      }
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6VectorInsertLowBackingStoreOffset &&
      instruction[0] == 0x4c && instruction[1] == 0x89 &&
      instruction[2] == 0x3c && instruction[3] == 0xc8 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t vector =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t index =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t value =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    static bool vector_insert_scratch_initialised = false;
    if (!vector_insert_scratch_initialised) {
      std::memset(g_stage6_vector_insert_scratch, 0,
                  sizeof(g_stage6_vector_insert_scratch));
      vector_insert_scratch_initialised = true;
    }

    if (vector >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(vector + 0x08, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(vector + 0x08))) {
      const uintptr_t scratch =
          reinterpret_cast<uintptr_t>(g_stage6_vector_insert_scratch);
      *reinterpret_cast<uintptr_t*>(vector + 0x08) = scratch;
      ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(scratch);
      if (g_stage6_gl_state_scratch_logs < 128) {
        char msg[680];
        int len = snprintf(msg, sizeof(msg),
                           "  [patch] restored Stage6 vector insert backing "
                           "rip_off=0x%lx vector=%p old_backing=%p scratch=%p "
                           "index=0x%lx value=%p count=%u\n",
                           static_cast<unsigned long>(libroblox_offset),
                           reinterpret_cast<void*>(vector), info->si_addr,
                           reinterpret_cast<void*>(scratch),
                           static_cast<unsigned long>(index),
                           reinterpret_cast<void*>(value),
                           IsReadableMemoryRange(vector, sizeof(uint32_t))
                               ? *reinterpret_cast<const uint32_t*>(vector)
                               : 0xffffffffu);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6VectorClearInvalidEntryFlagOffset &&
      instruction[0] == 0x41 && instruction[1] == 0xf6 &&
      instruction[2] == 0x47 && instruction[3] == 0xe8 &&
      instruction[4] == 0x01 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]) <
          kStage5LowAddressThreshold) {
    const uintptr_t vector =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t requested_end =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    if (g_stage6_gl_state_scratch_logs < 128) {
      char msg[620];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 vector clear invalid entry "
          "rip_off=0x%lx vector=%p current=%p requested_end=%p "
          "si_addr=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(vector),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
          reinterpret_cast<void*>(requested_end), info->si_addr);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_R15] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6VectorClearStoreEndOffset);
    return;
  }
  const bool rip_is_libroblox_text =
      g_libroblox_base != 0 &&
      instruction_address >= g_libroblox_base + kLibrobloxTextStartOffset &&
      instruction_address <
          g_libroblox_base + kLibrobloxExecutableSegmentEndOffset;
  if (g_current_stage >= 6 && g_init_with_params_recovery_in_progress != 0 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_INIT_NON_CODE_CALLBACK") &&
      g_libroblox_base != 0 && instruction_address > 0 &&
      !rip_is_libroblox_text) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      const uintptr_t return_address = *reinterpret_cast<const uintptr_t*>(rsp);
      const uintptr_t return_offset = return_address >= g_libroblox_base
                                          ? return_address - g_libroblox_base
                                          : 0;
      if (return_offset >= kLibrobloxTextStartOffset &&
          return_offset < kLibrobloxExecutableSegmentEndOffset) {
        if (g_stage6_gl_state_scratch_logs < 128) {
          char msg[560];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] skipped Stage6 init non-code callback target "
              "rip_off=0x%lx return_off=0x%lx rax=%p rdi=%p r15=%p\n",
              static_cast<unsigned long>(libroblox_offset),
              static_cast<unsigned long>(return_offset),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        ucontext->uc_mcontext.gregs[REG_RAX] = 0;
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rsp + sizeof(uintptr_t));
        return;
      }
    }
  }
  if (g_current_stage >= 6 && g_start_lua_app_dm_recovery_in_progress != 0 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NON_CODE_CALLBACK") &&
      libroblox_base == g_libroblox_base && instruction_address > 0 &&
      !rip_is_libroblox_text) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      const uintptr_t return_address = *reinterpret_cast<const uintptr_t*>(rsp);
      const uintptr_t return_offset = return_address >= libroblox_base
                                          ? return_address - libroblox_base
                                          : 0;
      if (return_offset >= kLibrobloxTextStartOffset &&
          return_offset < kLibrobloxExecutableSegmentEndOffset) {
        if (g_stage6_gl_state_scratch_logs < 128) {
          char msg[520];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] skipped Stage6 StartLua non-code callback target "
              "rip_off=0x%lx return_off=0x%lx rax=%p rdi=%p\n",
              static_cast<unsigned long>(libroblox_offset),
              static_cast<unsigned long>(return_offset),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        ucontext->uc_mcontext.gregs[REG_RAX] = 0;
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rsp + sizeof(uintptr_t));
        return;
      }
    }
  }
  if (g_current_stage >= 6 && instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6AtomicBitmapMidJumpOffset &&
      instruction[0] == 0x00 && instruction[1] == 0x00 &&
      instruction[2] == 0x48 && instruction[3] == 0x85 &&
      instruction[4] == 0xdb) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] realigned Stage6 atomic bitmap mid-jump rip_off=0x%lx "
        "to 0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        static_cast<unsigned long>(kStage6AtomicBitmapPostJumpOffset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6AtomicBitmapPostJumpOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6StartLuaDeepHashBucketCountReadOffset &&
      instruction[0] == 0x4c && instruction[1] == 0x8b &&
      instruction[2] == 0x6f && instruction[3] == 0x08 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    uintptr_t caller = 0;
    const uintptr_t frame =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    if (IsReadableMemoryRange(frame + sizeof(uintptr_t), sizeof(uintptr_t))) {
      caller = *reinterpret_cast<const uintptr_t*>(frame + sizeof(uintptr_t));
    }
    uintptr_t grandcaller = 0;
    uintptr_t caller_frame = 0;
    if (IsReadableMemoryRange(frame, sizeof(uintptr_t))) {
      caller_frame = *reinterpret_cast<const uintptr_t*>(frame);
    }
    if (IsReadableMemoryRange(caller_frame + sizeof(uintptr_t),
                              sizeof(uintptr_t))) {
      grandcaller =
          *reinterpret_cast<const uintptr_t*>(caller_frame + sizeof(uintptr_t));
    }
    const uintptr_t caller_offset =
        (caller >= libroblox_base) ? caller - libroblox_base : 0;
    const uintptr_t grandcaller_offset =
        (grandcaller >= libroblox_base) ? grandcaller - libroblox_base : 0;
    char msg[620];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 deep StartLua hash lookup low table: "
        "returning miss rip_off=0x%lx caller_off=0x%lx grandcaller_off=0x%lx "
        "rdi=%p rsi=%p rdx=%p r12=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        static_cast<unsigned long>(caller_offset),
        static_cast<unsigned long>(grandcaller_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDeepHashLookupMissOffset);
    return;
  }
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_SYSTEM_DIALOG_MESSAGE_NULL_RESULT") &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6StartLuaDeepSystemDialogNullResultReadOffset &&
      instruction[0] == 0x4c && instruction[1] == 0x8b &&
      instruction[2] == 0x20 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    if (!IsDisabled("MOCKTAIL_STAGE6_START_LUA_SYSTEM_DIALOG_NULL_PATH")) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 deep StartLua system-dialog null result: "
          "taking native null path rip_off=0x%lx rax=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_R12] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaDeepSystemDialogNullTestOffset);
      return;
    }

    char msg[460];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] substituted empty Stage6 deep StartLua system-dialog "
        "message object rip_off=0x%lx rax=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    std::memset(g_stage6_start_lua_system_dialog_object_scratch, 0,
                sizeof(g_stage6_start_lua_system_dialog_object_scratch));
    std::memset(g_stage6_start_lua_system_dialog_list_scratch, 0,
                sizeof(g_stage6_start_lua_system_dialog_list_scratch));
    std::memset(g_stage6_start_lua_system_dialog_item_scratch, 0,
                sizeof(g_stage6_start_lua_system_dialog_item_scratch));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_system_dialog_object_scratch,
        sizeof(g_stage6_start_lua_system_dialog_object_scratch));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_system_dialog_list_scratch,
        sizeof(g_stage6_start_lua_system_dialog_list_scratch));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_system_dialog_item_scratch,
        sizeof(g_stage6_start_lua_system_dialog_item_scratch));
    if (IsEnabled("MOCKTAIL_STAGE6_START_LUA_SYSTEM_DIALOG_LIST_ITEM")) {
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_system_dialog_list_scratch + 0x08) =
          reinterpret_cast<uintptr_t>(
              g_stage6_start_lua_system_dialog_item_scratch);
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_system_dialog_list_scratch + 0x10) =
          reinterpret_cast<uintptr_t>(
              g_stage6_start_lua_system_dialog_item_scratch + 0x30);
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_system_dialog_list_scratch + 0x18) =
          reinterpret_cast<uintptr_t>(
              g_stage6_start_lua_system_dialog_item_scratch + 0x30);
    }
    *reinterpret_cast<uintptr_t*>(
        g_stage6_start_lua_system_dialog_object_scratch) =
        reinterpret_cast<uintptr_t>(
            g_stage6_start_lua_system_dialog_list_scratch);
    ucontext->uc_mcontext.gregs[REG_RAX] = reinterpret_cast<greg_t>(
        g_stage6_start_lua_system_dialog_object_scratch);
    return;
  }
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_INIT_SYSTEM_DIALOG_NULL_RESULT") &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6InitSystemDialogNullResultReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x18 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    char msg[520];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 init system-dialog null result: "
                 "taking native null path rip_off=0x%lx rax=%p r15=%p r14=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6InitSystemDialogNullTestOffset);
    return;
  }
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NULL_CONTINUATION_ADDREF") &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6StartLuaNullContinuationAddrefOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x01 &&
      !IsReadableMemoryRange(
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]),
          sizeof(uint32_t))) {
    char msg[480];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartLua null-continuation addref target "
                 "unreadable: treating as null rip_off=0x%lx rcx=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaNullContinuationNullRefOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6StringAssignNullDestReadOffset &&
      instruction[0] == 0xf6 && instruction[1] == 0x07 &&
      instruction[2] == 0x01 && ucontext->uc_mcontext.gregs[REG_RDI] == 0) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 string assign null destination: returning null "
        "rip_off=0x%lx rsi=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6StringAssignReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6InitParamsNullSourceCopyOffset &&
      instruction[0] == 0x0f && instruction[1] == 0x10 &&
      instruction[2] == 0x06 && ucontext->uc_mcontext.gregs[REG_RSI] == 0 &&
      ucontext->uc_mcontext.gregs[REG_RDI] != 0) {
    auto* dest =
        reinterpret_cast<unsigned char*>(ucontext->uc_mcontext.gregs[REG_RDI]);
    std::memset(g_stage6_init_params_holder_scratch, 0,
                sizeof(g_stage6_init_params_holder_scratch));
    std::memset(dest, 0, 0x38);
    *reinterpret_cast<uintptr_t*>(dest + 0x00) =
        reinterpret_cast<uintptr_t>(g_stage6_init_params_holder_scratch);
    constexpr uint64_t kDefaultBits = 0x803fffffffffff00ULL;
    std::memcpy(dest + 0x28, &kDefaultBits, sizeof(kDefaultBits));

    char msg[380];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 init-param aggregate null source: "
                 "zero-initialized dest=%p holder=%p rip_off=0x%lx\n",
                 dest, static_cast<void*>(g_stage6_init_params_holder_scratch),
                 static_cast<unsigned long>(libroblox_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6InitParamsCopyEpilogueOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6HashLookupLowTableReadOffset &&
      instruction[0] == 0x8b && instruction[1] == 0x5f &&
      instruction[2] == 0x10 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    if (ShouldLogStage6Repeated(&g_stage6_hash_lookup_low_table_logs)) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 hash lookup low table: using empty path "
          "rip_off=0x%lx table=%p out=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6HashLookupEmptyPathOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6NestedHashLookupLowTableReadOffset &&
      instruction[0] == 0x44 && instruction[1] == 0x8b &&
      instruction[2] == 0x67 && instruction[3] == 0x10 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    char msg[360];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 nested hash lookup low table: using empty path "
        "rip_off=0x%lx table=%p out=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6NestedHashLookupEmptyPathOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StringReleaseNullOwnerReadOffset &&
      instruction[0] == 0x44 && instruction[1] == 0x8b &&
      instruction[2] == 0x7b && instruction[3] == 0x38 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t scratch =
        reinterpret_cast<uintptr_t>(g_stage6_start_app_release_owner_scratch);
    const uintptr_t empty_slot = reinterpret_cast<uintptr_t>(
        &g_stage6_start_app_release_owner_empty_slot);
    g_stage6_start_app_release_owner_empty_slot = 0;
    *reinterpret_cast<uintptr_t*>(scratch + 0x28) = empty_slot;
    *reinterpret_cast<uint32_t*>(scratch + 0x38) = 0;
    char msg[440];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 string release null owner: using scratch owner "
        "rip_off=0x%lx owner=%p scratch=%p slot=%p value=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        reinterpret_cast<void*>(scratch), reinterpret_cast<void*>(empty_slot),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(scratch);
    ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(scratch + 0x28);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppPayloadMapNullOwnerReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x7b && instruction[3] == 0x28 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t scratch =
        reinterpret_cast<uintptr_t>(g_stage6_start_app_payload_owner_scratch);
    char msg[420];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartApp/StartLua payload map null owner: "
                 "using scratch owner "
                 "rip_off=0x%lx owner=%p scratch=%p key=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
                 reinterpret_cast<void*>(scratch),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(scratch);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppPayloadHashLowTableReadOffset &&
      instruction[0] == 0x44 && instruction[1] == 0x8b &&
      instruction[2] == 0x6f && instruction[3] == 0x10 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    char msg[360];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartApp/StartLua payload hash low table: "
                 "using empty path "
                 "rip_off=0x%lx table=%p out=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppPayloadHashEmptyPathOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      ((libroblox_offset == kStage6StartAppPayloadLinkLoadOffset &&
        instruction[0] == 0x48 && instruction[1] == 0x8b &&
        instruction[2] == 0x00) ||
       (libroblox_offset == kStage6StartAppPayloadLinkStoreOffset &&
        instruction[0] == 0x48 && instruction[1] == 0x89 &&
        instruction[2] == 0x18)) &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    char msg[400];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartApp/StartLua payload link null slot: using "
        "scratch slot "
        "rip_off=0x%lx op=%s slot=%p current=%p frame=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        libroblox_offset == kStage6StartAppPayloadLinkLoadOffset ? "load"
                                                                 : "store",
        static_cast<void*>(&g_stage6_start_app_payload_link_slot),
        reinterpret_cast<void*>(g_stage6_start_app_payload_link_slot),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(&g_stage6_start_app_payload_link_slot);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppPayloadMapLookupLowOwnerReadOffset &&
      instruction[0] == 0x8b && instruction[1] == 0x53 &&
      instruction[2] == 0x38 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
          kStage5LowAddressThreshold) {
    const uintptr_t scratch = reinterpret_cast<uintptr_t>(
        g_stage6_start_app_payload_map_lookup_owner_scratch);
    char msg[440];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartApp/StartLua payload map lookup low "
                 "owner: using scratch owner "
                 "rip_off=0x%lx owner=%p scratch=%p key=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
                 reinterpret_cast<void*>(scratch),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(scratch);
    ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(scratch + 0x28);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppCollectionManagerNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x07 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartApp/StartLua collection manager null: returning "
        "no-op "
        "rip_off=0x%lx collection=%p descriptor=%p owner=%p value=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) +
            0x08)),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppCollectionManagerReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppFallbackHandlerNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x07 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    const uintptr_t source =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    char msg[560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartApp fallback handler null: returning empty "
        "rip_off=0x%lx source=%p handler_slot=%p payload=%p frame=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(source),
        reinterpret_cast<void*>(ReadPointerIfReadable(source + 0x88)),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppFallbackHandlerAfterCallOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (libroblox_offset == kStage6MapLookupLowOwnerReadOffset ||
       libroblox_offset == kStage6StringMapLookupLowOwnerReadOffset) &&
      instruction[0] == 0x8b && instruction[1] == 0x53 &&
      instruction[2] == 0x38 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
          kStage5LowAddressThreshold) {
    const bool is_string_map_lookup =
        libroblox_offset == kStage6StringMapLookupLowOwnerReadOffset;
    uintptr_t return_offset = is_string_map_lookup
                                  ? kStage6StringMapLookupUnlockAndReturnOffset
                                  : kStage6MapLookupUnlockAndReturnOffset;
    if (is_string_map_lookup &&
        (g_start_app_with_params_recovery_in_progress != 0 ||
         g_start_lua_app_dm_recovery_in_progress != 0)) {
      const uintptr_t scratch_string = SeedStage6StringFieldValueScratch(
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]));
      if (scratch_string != 0) {
        if (ShouldLogStage6Repeated(&g_stage6_string_map_scratch_logs)) {
          char msg[440];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] Stage6 string map lookup low owner: using scratch "
              "string "
              "rip_off=0x%lx owner=%p key=%p value=%p\n",
              static_cast<unsigned long>(libroblox_offset),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
              reinterpret_cast<void*>(scratch_string));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
        }
        ++g_skipped_headless_null_writes;
        g_stage6_string_field_null_current_loop_count = 0;
        g_stage6_string_field_null_current_last_value = 0;
        ucontext->uc_mcontext.gregs[REG_R14] =
            static_cast<greg_t>(scratch_string);
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(libroblox_base + return_offset);
        return;
      }
    }
    if (ShouldLogStage6Repeated(&g_stage6_map_lookup_low_owner_logs)) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 map lookup low owner: returning null "
          "rip_off=0x%lx owner=%p key=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + return_offset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6StringFieldNullCurrentReadOffset &&
      instruction[0] == 0x0f && instruction[1] == 0xb6 &&
      instruction[2] == 0x38 && ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    const uintptr_t value =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    if (g_start_lua_app_dm_recovery_in_progress != 0 ||
        g_start_app_with_params_recovery_in_progress != 0) {
      if (g_stage6_string_field_null_current_last_value == value) {
        ++g_stage6_string_field_null_current_loop_count;
      } else {
        g_stage6_string_field_null_current_last_value = value;
        g_stage6_string_field_null_current_loop_count = 1;
      }
      if (g_stage6_string_field_null_current_loop_count >
          kStage6StringFieldNullLoopLimit) {
        if (TryReturnFromRepeatedStage6StringFieldLoop(
                ucontext, libroblox_base, libroblox_offset, value)) {
          return;
        }
      }
    }
    if (ShouldLogStage6Repeated(&g_stage6_string_field_assign_logs)) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 string field null current: assigning new value "
          "rip_off=0x%lx object=%p value=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(value));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R12] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StringFieldAssignPathOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6StringFieldNullOldReleaseOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x48 && instruction[3] == 0x18 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    if (ShouldLogStage6Repeated(&g_stage6_string_field_old_value_logs)) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 string field null old value: skipping release "
          "rip_off=0x%lx slot=%p new_value=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + kStage6StringFieldStoreNewOffset);
    return;
  }
  const bool stage6_unsupported_message_slot_deref =
      libroblox_offset == kStage6UnsupportedMessageSlotDerefOffset ||
      libroblox_offset == kStage6StartLuaUnsupportedMessageSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessagePromptSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageEntrySlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageEnumSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageLoopSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTailSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail2SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail3SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail4SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail5SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail6SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail7SlotDerefOffset ||
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageTail8SlotDerefOffset ||
      libroblox_offset == kStage6StartAppUnsupportedMessageSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartAppUnsupportedMessageDetailSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartAppUnsupportedMessagePostInstanceSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartAppUnsupportedMessageDeepSlotDerefOffset ||
      libroblox_offset ==
          kStage6StartAppUnsupportedMessagePostHashSlotDerefOffset;
  const bool stage6_unsupported_message_slot_load =
      (instruction[0] == 0x4c && instruction[1] == 0x8b &&
       instruction[2] == 0x30) ||
      (instruction[0] == 0x48 && instruction[1] == 0x8b &&
       (instruction[2] == 0x00 || instruction[2] == 0x18 ||
        instruction[2] == 0x30));
  const bool stage6_start_app_unsupported_message_proxy_read =
      libroblox_offset ==
          kStage6StartAppUnsupportedMessageProxyObjectReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x07;
  const bool stage6_start_app_unsupported_message_proxy_state_test =
      libroblox_offset ==
          kStage6StartAppUnsupportedMessageProxyObjectStateTestOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x83 &&
      instruction[2] == 0x78 && instruction[3] == 0x08 &&
      instruction[4] == 0x00;
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      (stage6_start_app_unsupported_message_proxy_read ||
       stage6_start_app_unsupported_message_proxy_state_test) &&
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_PROXY")) {
    const uintptr_t proxy =
        stage6_start_app_unsupported_message_proxy_read
            ? static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI])
            : static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const bool unreadable_proxy =
        proxy < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(proxy, sizeof(uintptr_t));
    if (unreadable_proxy) {
      static volatile sig_atomic_t null_proxy_logs = 0;
      if (null_proxy_logs < 32) {
        char msg[620];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] Stage6 StartLua unsupported-message null proxy: "
            "taking empty return rip_off=0x%lx which=%s proxy=%p rdi=%p "
            "rax=%p rsi=%p si_addr=%p\n",
            static_cast<unsigned long>(libroblox_offset),
            stage6_start_app_unsupported_message_proxy_read ? "object"
                                                            : "state",
            reinterpret_cast<void*>(proxy),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
            info->si_addr);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++null_proxy_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base +
          kStage6StartAppUnsupportedMessageProxyObjectReturnOffset);
      return;
    }
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartLuaUnsupportedMessageVectorReadOffset &&
      instruction[0] == 0x4c && instruction[1] == 0x8b &&
      instruction[2] == 0x30 &&
      IsEnabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_EMPTY_VECTOR")) {
    const uintptr_t vector =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const bool unreadable_vector =
        vector < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(vector, 2 * sizeof(uintptr_t));
    if (unreadable_vector) {
      std::memset(
          g_stage6_start_lua_unsupported_message_empty_vector_scratch, 0,
          sizeof(g_stage6_start_lua_unsupported_message_empty_vector_scratch));
      static volatile sig_atomic_t empty_vector_logs = 0;
      if (empty_vector_logs < 32) {
        char msg[540];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] Stage6 StartLua unsupported-message empty vector: "
            "using scratch vector rip_off=0x%lx vector=%p scratch=%p "
            "rdi=%p rsi=%p si_addr=%p\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(vector),
            static_cast<void*>(
                g_stage6_start_lua_unsupported_message_empty_vector_scratch),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
            info->si_addr);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++empty_vector_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = reinterpret_cast<greg_t>(
          g_stage6_start_lua_unsupported_message_empty_vector_scratch);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 && stage6_unsupported_message_slot_deref &&
      stage6_unsupported_message_slot_load &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    SeedStage6GlUnsupportedMessageSlot();
    volatile sig_atomic_t* logs =
        libroblox_offset == kStage6UnsupportedMessageSlotDerefOffset
            ? &g_stage6_unsupported_message_slot_logs
            : &g_stage6_start_lua_unsupported_message_slot_logs;
    if (ShouldLogStage6Repeated(logs)) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 unsupported-message slot null: using fallback "
          "rip_off=0x%lx slot=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          static_cast<void*>(&g_stage6_gl_unsupported_message_slot));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(&g_stage6_gl_unsupported_message_slot);
    return;
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageThreadStateReadOffset &&
      instruction[0] == 0x41 && instruction[1] == 0x0f &&
      instruction[2] == 0xb7 && instruction[3] == 0x8c &&
      instruction[4] == 0x24 && instruction[5] == 0x1a &&
      instruction[6] == 0x02 && instruction[7] == 0x00 &&
      instruction[8] == 0x00 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]) <
          kStage5LowAddressThreshold &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_"
                "THREAD_STATE")) {
    static volatile sig_atomic_t null_thread_state_logs = 0;
    if (null_thread_state_logs < 32) {
      char msg[620];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartLua unsupported-message null thread state: "
          "taking empty return rip_off=0x%lx rsi=%p r12=%p rax=%p "
          "owner=%p message=%p si_addr=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          info->si_addr);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++null_thread_state_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaUnsupportedMessageThreadStateReturnOffset);
    return;
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageParentThreadStateReadOffset &&
      instruction[0] == 0x41 && instruction[1] == 0x0f &&
      instruction[2] == 0xb7 && instruction[3] == 0x8f &&
      instruction[4] == 0x1a && instruction[5] == 0x02 &&
      instruction[6] == 0x00 && instruction[7] == 0x00 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]) <
          kStage5LowAddressThreshold &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_"
                "PARENT_STATE")) {
    static volatile sig_atomic_t null_parent_state_logs = 0;
    if (null_parent_state_logs < 32) {
      char msg[620];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartLua unsupported-message null parent state: "
          "taking empty return rip_off=0x%lx r15=%p r12=%p rax=%p "
          "owner=%p message=%p si_addr=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          info->si_addr);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++null_parent_state_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaUnsupportedMessageParentThreadStateReturnOffset);
    return;
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset ==
          kStage6StartLuaUnsupportedMessageLeafThreadStateReadOffset &&
      instruction[0] == 0x0f && instruction[1] == 0xb7 &&
      instruction[2] == 0x8b && instruction[3] == 0x1a &&
      instruction[4] == 0x02 && instruction[5] == 0x00 &&
      instruction[6] == 0x00 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
          kStage5LowAddressThreshold &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_LEAF_"
                "STATE")) {
    static volatile sig_atomic_t null_leaf_state_logs = 0;
    if (null_leaf_state_logs < 32) {
      char msg[620];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartLua unsupported-message null leaf state: "
          "taking empty return rip_off=0x%lx rbx=%p r14=%p rax=%p "
          "rdi=%p rsi=%p si_addr=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          info->si_addr);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++null_leaf_state_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaUnsupportedMessageLeafThreadStateReturnOffset);
    return;
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      (libroblox_offset == kStage6StartLuaPreviousStateFlagReadOffset ||
       libroblox_offset == kStage6StartLuaCurrentStateFlagReadOffset) &&
      instruction[0] == 0x0a &&
      ((libroblox_offset == kStage6StartLuaPreviousStateFlagReadOffset &&
        instruction[1] == 0x81 &&
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]) <
            kStage5LowAddressThreshold) ||
       (libroblox_offset == kStage6StartLuaCurrentStateFlagReadOffset &&
        instruction[1] == 0x8a &&
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]) <
            kStage5LowAddressThreshold)) &&
      instruction[2] == 0x08 && instruction[3] == 0x02 &&
      instruction[4] == 0x00 && instruction[5] == 0x00 &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_STATE_FLAG_NULL_SOURCE")) {
    const bool current =
        libroblox_offset == kStage6StartLuaCurrentStateFlagReadOffset;
    const uintptr_t object = static_cast<uintptr_t>(
        ucontext->uc_mcontext.gregs[current ? REG_R14 : REG_R12]);
    const uintptr_t source = static_cast<uintptr_t>(
        ucontext->uc_mcontext.gregs[current ? REG_RDX : REG_RCX]);
    static volatile sig_atomic_t state_flag_null_logs = 0;
    if (state_flag_null_logs < 32) {
      char msg[620];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartLua state flag null source: "
          "keeping local flag rip_off=0x%lx which=%s object=%p "
          "source=%p object18=%p si_addr=%p al=0x%02x cl=0x%02x\n",
          static_cast<unsigned long>(libroblox_offset),
          current ? "current" : "previous", reinterpret_cast<void*>(object),
          reinterpret_cast<void*>(source),
          reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x18)),
          info->si_addr,
          static_cast<unsigned>(ucontext->uc_mcontext.gregs[REG_RAX] & 0xff),
          static_cast<unsigned>(ucontext->uc_mcontext.gregs[REG_RCX] & 0xff));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++state_flag_null_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 6;
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      g_start_app_with_params_recovery_in_progress != 0 &&
      libroblox_offset == kStage6PlatformHeadersVectorMoveStoreOffset &&
      instruction[0] == 0x0f && instruction[1] == 0x11 &&
      instruction[2] == 0x09 &&
      reinterpret_cast<uintptr_t>(info->si_addr) ==
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX])) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t vector =
        rbp >= 0x88 ? ReadPointerIfReadable(rbp - 0x88) : 0;
    const uintptr_t new_begin =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    const uintptr_t dest =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t old_src =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t old_end =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t scratch_begin =
        reinterpret_cast<uintptr_t>(g_stage6_platform_headers_vector_scratch);
    const size_t scratch_size =
        sizeof(g_stage6_platform_headers_vector_scratch);
    const bool vector_writable =
        vector >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(vector, 3 * sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(vector)) &&
        EnsureWritablePage(
            reinterpret_cast<void*>(vector + 2 * sizeof(uintptr_t)));
    if (vector_writable) {
      std::memset(g_stage6_platform_headers_vector_scratch, 0, 0x100);

      size_t prefix_bytes = 0;
      if (dest >= new_begin) {
        prefix_bytes = static_cast<size_t>(dest - new_begin);
        prefix_bytes &= ~static_cast<size_t>(0x0f);
        if (prefix_bytes > scratch_size ||
            !IsReadableMemoryRange(new_begin, prefix_bytes)) {
          prefix_bytes = 0;
        }
      }

      size_t written = 0;
      if (prefix_bytes > 0) {
        std::memcpy(g_stage6_platform_headers_vector_scratch,
                    reinterpret_cast<const void*>(new_begin), prefix_bytes);
        written = prefix_bytes;
      } else if (IsReadableMemoryRange(new_begin, 0x10)) {
        std::memcpy(g_stage6_platform_headers_vector_scratch,
                    reinterpret_cast<const void*>(new_begin), 0x10);
        written = 0x10;
      }

      size_t remaining_bytes = 0;
      if (old_end >= old_src && written < scratch_size) {
        remaining_bytes = static_cast<size_t>(old_end - old_src);
        remaining_bytes &= ~static_cast<size_t>(0x0f);
        if (remaining_bytes > scratch_size - written ||
            !IsReadableMemoryRange(old_src, remaining_bytes)) {
          remaining_bytes = 0;
        }
      }
      if (remaining_bytes > 0) {
        std::memcpy(g_stage6_platform_headers_vector_scratch + written,
                    reinterpret_cast<const void*>(old_src), remaining_bytes);
        written += remaining_bytes;
      }

      *reinterpret_cast<uintptr_t*>(vector + 0x00) = scratch_begin;
      *reinterpret_cast<uintptr_t*>(vector + 0x08) = scratch_begin + written;
      *reinterpret_cast<uintptr_t*>(vector + 0x10) =
          scratch_begin + scratch_size;

      static volatile sig_atomic_t platform_header_vector_logs = 0;
      if (platform_header_vector_logs < 32) {
        char msg[620];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] rebuilt Stage6 platform-headers vector "
            "rip_off=0x%lx vector=%p old_src=%p old_end=%p "
            "bad_dest=%p scratch=%p prefix=0x%lx remaining=0x%lx "
            "written=0x%lx\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(vector), reinterpret_cast<void*>(old_src),
            reinterpret_cast<void*>(old_end), reinterpret_cast<void*>(dest),
            reinterpret_cast<void*>(scratch_begin),
            static_cast<unsigned long>(prefix_bytes),
            static_cast<unsigned long>(remaining_bytes),
            static_cast<unsigned long>(written));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++platform_header_vector_logs;
      }

      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(scratch_begin);
      ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(scratch_begin);
      ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(scratch_begin);
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6PlatformHeadersVectorMoveReturnOffset);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppInvalidVectorRefcountReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x5f && instruction[3] == 0x08) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t refcount_slot = object + 0x08;
    const bool faulted_refcount =
        reinterpret_cast<uintptr_t>(info->si_addr) == refcount_slot;
    const bool invalid_object =
        !IsLikelyUserPointer(object) || object > UINTPTR_MAX - 0x10;
    if (invalid_object || faulted_refcount) {
      static volatile sig_atomic_t invalid_vector_refcount_read_logs = 0;
      if (invalid_vector_refcount_read_logs < 32) {
        char msg[380];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 StartApp invalid vector refcount read "
            "rip_off=0x%lx object=%p refcount_slot=%p faulted=%d "
            "return_off=0x%lx\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(object),
            reinterpret_cast<void*>(refcount_slot), faulted_refcount ? 1 : 0,
            static_cast<unsigned long>(
                kStage6StartAppInvalidVectorDestructorSkipOffset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++invalid_vector_refcount_read_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = -1;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartAppInvalidVectorDestructorSkipOffset);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppInvalidVectorReleaseOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0x48 &&
      instruction[2] == 0x0f && instruction[3] == 0xc1 &&
      instruction[4] == 0x43 && instruction[5] == 0x08) {
    const uintptr_t base =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t refcount_slot = base + 0x08;
    const uintptr_t fallback_begin =
        reinterpret_cast<uintptr_t>(g_stage5_fallback_region);
    const uintptr_t fallback_end =
        fallback_begin + sizeof(g_stage5_fallback_region);
    const bool synthetic_fallback =
        base >= fallback_begin && base < fallback_end;
    const bool faulted_refcount =
        reinterpret_cast<uintptr_t>(info->si_addr) == refcount_slot;
    if (synthetic_fallback || faulted_refcount || base > UINTPTR_MAX - 0x10 ||
        !IsReadableMemoryRange(refcount_slot, sizeof(uint64_t))) {
      static volatile sig_atomic_t invalid_vector_release_logs = 0;
      if (invalid_vector_release_logs < 32) {
        char msg[360];
        int len =
            snprintf(msg, sizeof(msg),
                     "  [patch] skipped Stage6 StartApp invalid vector release "
                     "rip_off=0x%lx base=%p refcount_slot=%p synthetic=%d "
                     "faulted=%d\n",
                     static_cast<unsigned long>(libroblox_offset),
                     reinterpret_cast<void*>(base),
                     reinterpret_cast<void*>(refcount_slot),
                     synthetic_fallback ? 1 : 0, faulted_refcount ? 1 : 0);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++invalid_vector_release_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = -1;
      ucontext->uc_mcontext.gregs[REG_RIP] += 6;
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0) &&
      libroblox_offset == kStage6StartAppInvalidVectorDestructorCallOffset &&
      instruction[0] == 0xff && instruction[1] == 0x50 &&
      instruction[2] == 0x10) {
    const uintptr_t vtable =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t target =
        IsReadableMemoryRange(vtable + 0x10, sizeof(uintptr_t))
            ? ReadPointerIfReadable(vtable + 0x10)
            : 0;
    if (vtable < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(vtable + 0x10, sizeof(uintptr_t)) ||
        !IsLikelyUserPointer(target)) {
      static volatile sig_atomic_t invalid_vector_destructor_logs = 0;
      if (invalid_vector_destructor_logs < 32) {
        char msg[420];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 invalid vector destructor "
            "rip_off=0x%lx object=%p vtable=%p target=%p "
            "return_off=0x%lx\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
            reinterpret_cast<void*>(vtable), reinterpret_cast<void*>(target),
            static_cast<unsigned long>(
                kStage6StartAppInvalidVectorDestructorSkipOffset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++invalid_vector_destructor_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = -1;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartAppInvalidVectorDestructorSkipOffset);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6UnsupportedMessageSlotStoreReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x1f && ucontext->uc_mcontext.gregs[REG_RDI] == 0) {
    SeedStage6GlUnsupportedMessageSlot();
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 unsupported-message store null slot: using fallback "
        "rip_off=0x%lx value=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(&g_stage6_gl_unsupported_message_slot);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6SharedPtrNullAddrefOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x40 && instruction[3] == 0x18 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    char msg[320];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 shared pointer null addref: skipping "
                 "rip_off=0x%lx slot=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6SharedPtrAddrefReturnOffset);
    return;
  }
  if (signo == SIGSEGV && g_current_stage >= 6 && info &&
      instruction_readable && libroblox_base != 0 &&
      g_start_lua_app_dm_recovery_in_progress != 0 &&
      libroblox_offset == kStage6SharedPtrInvalidAddrefOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x47 && instruction[3] == 0x08 &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_SHARED_PTR_INVALID_ADDREF_"
                "CONTROL_BLOCK")) {
    const uintptr_t control_block =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t return_address = ReadPointerIfReadable(rsp);
    const uintptr_t return_offset =
        return_address >= libroblox_base ? return_address - libroblox_base : 0;
    const bool unreadable_control_block =
        control_block < kStage5LowAddressThreshold ||
        control_block > UINTPTR_MAX - 0x18 ||
        !IsReadableMemoryRange(control_block + 0x08, sizeof(uint64_t));
    if (unreadable_control_block &&
        return_offset == kStage6SharedPtrInvalidAddrefCopyReturnOffset) {
      const uintptr_t dest_pair =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
      const uintptr_t copied_value = ReadPointerIfReadable(dest_pair);
      const bool unreadable_copied_value =
          copied_value != 0 &&
          (copied_value < kStage5LowAddressThreshold ||
           !IsReadableMemoryRange(copied_value, sizeof(uintptr_t)));
      if (unreadable_copied_value &&
          IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_SHARED_PTR_INVALID_ADDREF_"
                    "EMPTY_OBJECT") &&
          dest_pair >= kStage5LowAddressThreshold &&
          IsReadableMemoryRange(dest_pair, 2 * sizeof(uintptr_t)) &&
          EnsureWritablePage(reinterpret_cast<void*>(dest_pair)) &&
          EnsureWritablePage(
              reinterpret_cast<void*>(dest_pair + sizeof(uintptr_t)))) {
        *reinterpret_cast<uintptr_t*>(dest_pair) = 0;
        *reinterpret_cast<uintptr_t*>(dest_pair + sizeof(uintptr_t)) = 0;
        static volatile sig_atomic_t invalid_empty_object_logs = 0;
        if (invalid_empty_object_logs < 32) {
          char msg[720];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] Stage6 StartLua shared pointer invalid object: "
              "returning empty copy rip_off=0x%lx control=%p copied_value=%p "
              "dest=%p source_pair=%p return=%p/off=0x%lx\n",
              static_cast<unsigned long>(libroblox_offset),
              reinterpret_cast<void*>(control_block),
              reinterpret_cast<void*>(copied_value),
              reinterpret_cast<void*>(dest_pair),
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
              reinterpret_cast<void*>(return_address),
              static_cast<unsigned long>(return_offset));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++invalid_empty_object_logs;
        }
        ++g_skipped_headless_null_writes;
        ucontext->uc_mcontext.gregs[REG_RAX] = 0;
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rsp + sizeof(uintptr_t));
        ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
            libroblox_base +
            kStage6SharedPtrInvalidAddrefCopySuccessReturnOffset);
        return;
      }
      std::memset(g_stage6_shared_ptr_invalid_addref_control_block, 0,
                  sizeof(g_stage6_shared_ptr_invalid_addref_control_block));
      *reinterpret_cast<uintptr_t*>(
          g_stage6_shared_ptr_invalid_addref_control_block) =
          reinterpret_cast<uintptr_t>(kFallbackVtable);
      *reinterpret_cast<uint64_t*>(
          g_stage6_shared_ptr_invalid_addref_control_block + 0x08) = 0x100000;
      *reinterpret_cast<uint64_t*>(
          g_stage6_shared_ptr_invalid_addref_control_block + 0x10) = 0x100000;
      static volatile sig_atomic_t invalid_addref_logs = 0;
      if (invalid_addref_logs < 32) {
        char msg[620];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] Stage6 StartLua shared pointer invalid addref: "
            "using scratch control block rip_off=0x%lx control=%p "
            "si_addr=%p scratch=%p return=%p/off=0x%lx copied_value=%p\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(control_block), info->si_addr,
            static_cast<void*>(
                g_stage6_shared_ptr_invalid_addref_control_block),
            reinterpret_cast<void*>(return_address),
            static_cast<unsigned long>(return_offset),
            reinterpret_cast<void*>(copied_value));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++invalid_addref_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RDI] = reinterpret_cast<greg_t>(
          g_stage6_shared_ptr_invalid_addref_control_block);
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6SharedPtrCopyNullSourceRefcountOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x40 && instruction[3] == 0x18 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    const uintptr_t rbx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t copied_value = ReadPointerIfReadable(rbx);
    const uintptr_t stack_return =
        ReadPointerIfReadable(rsp + 3 * sizeof(uintptr_t));
    const uintptr_t return_offset =
        stack_return >= libroblox_base ? stack_return - libroblox_base : 0;
    char msg[480];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 shared pointer copy null source: skipping addref "
        "rip_off=0x%lx slot=%p copied_value=%p stack_return=%p/"
        "off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(rbx), reinterpret_cast<void*>(copied_value),
        reinterpret_cast<void*>(stack_return),
        static_cast<unsigned long>(return_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6SharedPtrCopyNullSourceReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6SharedPtrReleaseNullSourceRefcountOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x48 && instruction[3] == 0x18 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    const uintptr_t rbx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t release_slot_value = ReadPointerIfReadable(rbx);
    const uintptr_t stack_return =
        ReadPointerIfReadable(rsp + 3 * sizeof(uintptr_t));
    const uintptr_t return_offset =
        stack_return >= libroblox_base ? stack_return - libroblox_base : 0;
    char msg[480];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 shared pointer null release: skipping release "
        "rip_off=0x%lx slot=%p release_slot_value=%p stack_return=%p/"
        "off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(rbx),
        reinterpret_cast<void*>(release_slot_value),
        reinterpret_cast<void*>(stack_return),
        static_cast<unsigned long>(return_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6SharedPtrReleaseNullSourceReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6PlatformHeaderValueNullTestOffset &&
      instruction[0] == 0x41 && instruction[1] == 0xf6 &&
      instruction[2] == 0x06 && instruction[3] == 0x01 &&
      ucontext->uc_mcontext.gregs[REG_R14] == 0) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t holder = ReadPointerIfReadable(rbp - 0x80);
    const uintptr_t object = ReadPointerIfReadable(holder);
    const uintptr_t vtable = ReadPointerIfReadable(object);
    const uintptr_t getter = ReadPointerIfReadable(vtable + 0x40);
    const uintptr_t value_slot = object + 0x268;
    const uintptr_t current_value = ReadPointerIfReadable(value_slot);
    bool seeded_value_slot = false;
    if (current_value == 0 &&
        IsReadableMemoryRange(value_slot, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(value_slot))) {
      *reinterpret_cast<uintptr_t*>(value_slot) =
          reinterpret_cast<uintptr_t>(g_stage6_platform_headers_zero_string);
      seeded_value_slot = true;
    }
    const uintptr_t final_value = ReadPointerIfReadable(value_slot);
    const uintptr_t getter_offset =
        getter >= libroblox_base ? getter - libroblox_base : 0;
    char msg[680];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 platform header numeric value null: using zero "
        "string "
        "rip_off=0x%lx holder=%p object=%p vtable=%p getter=%p/"
        "off=0x%lx value_slot=%p current_value=%p final_value=%p "
        "seeded=%d\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(holder), reinterpret_cast<void*>(object),
        reinterpret_cast<void*>(vtable), reinterpret_cast<void*>(getter),
        static_cast<unsigned long>(getter_offset),
        reinterpret_cast<void*>(value_slot),
        reinterpret_cast<void*>(current_value),
        reinterpret_cast<void*>(final_value), seeded_value_slot ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] =
        reinterpret_cast<greg_t>(g_stage6_platform_headers_zero_string);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6PlatformHeaderNullReleaseOffset &&
      instruction[0] == 0xf0 && instruction[1] == 0xff &&
      instruction[2] == 0x48 && instruction[3] == 0xf8 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    char msg[360];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 platform header null release: skipping "
                 "rip_off=0x%lx object=%p slot=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6PlatformHeaderNullReleaseReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6Utf8LengthInvalidPointerOffset &&
      instruction[0] == 0x8a && instruction[1] == 0x0f &&
      !IsReadableMemoryRange(
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]), 1)) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      const uintptr_t return_address = *reinterpret_cast<uintptr_t*>(rsp);
      const uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      const uintptr_t caller_scratch = rbp >= 0x38 ? rbp - 0x38 : 0;
      bool seeded_empty = false;
      if (IsReadableMemoryRange(caller_scratch, 1)) {
        *reinterpret_cast<unsigned char*>(caller_scratch) = 0;
        seeded_empty = true;
      }
      char msg[360];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 UTF-8 length invalid pointer: returning empty "
          "string rip_off=0x%lx ptr=%p ret=%p scratch=%p seeded=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(return_address),
          reinterpret_cast<void*>(caller_scratch), seeded_empty ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(return_address);
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp + sizeof(uintptr_t));
      return;
    }
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6OptionalStringNullReadOffset &&
      instruction[0] == 0x44 && instruction[1] == 0x0f &&
      instruction[2] == 0xb6 && instruction[3] == 0x28 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 optional string null result: treating as empty "
        "rip_off=0x%lx holder=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6OptionalStringLengthTestOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6UnsupportedMessageListHolderNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x18 && ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    char msg[320];
    int len = snprintf(msg, sizeof(msg),
                       "  [patch] Stage6 unsupported-message list holder null: "
                       "treating as empty rip_off=0x%lx\n",
                       static_cast<unsigned long>(libroblox_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6UnsupportedMessageListEmptyReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6UnsupportedMessageListNullReadOffset &&
      instruction[0] == 0x4c && instruction[1] == 0x8b &&
      instruction[2] == 0x33 && ucontext->uc_mcontext.gregs[REG_RBX] == 0) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 unsupported-message list null: treating as empty "
        "rip_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6UnsupportedMessageListEmptyReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && g_init_with_params_recovery_in_progress != 0 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_INIT_SINGLETON_LOCK_GLOBAL") &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6PostClientSettingsSingletonLockReadOffset &&
      instruction[0] == 0x8b && instruction[1] == 0x47 &&
      instruction[2] == 0x78 && ucontext->uc_mcontext.gregs[REG_RDI] == 0) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(
        g_stage6_post_client_settings_singleton_lock_scratch);
    std::memset(g_stage6_post_client_settings_singleton_lock_scratch, 0,
                sizeof(g_stage6_post_client_settings_singleton_lock_scratch));
    *reinterpret_cast<uint32_t*>(scratch) = 0;
    *reinterpret_cast<uint32_t*>(scratch + 0x78) = 2;

    bool stored_global = false;
    uintptr_t global =
        g_libroblox_base + kStage6PostClientSettingsSingletonLockGlobalOffset;
    if (IsReadableMemoryRange(global, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(global))) {
      *reinterpret_cast<uintptr_t*>(global) = scratch;
      stored_global = true;
    }

    bool stored_saved_rbx = false;
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    uintptr_t saved_rbx_slot =
        rbp >= sizeof(uintptr_t) ? rbp - sizeof(uintptr_t) : 0;
    if (IsReadableMemoryRange(saved_rbx_slot, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(saved_rbx_slot) = scratch;
      stored_saved_rbx = true;
    }

    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 init singleton lock missing: using scratch "
        "object=%p global=%p stored_global=%d saved_rbx=%d rip_off=0x%lx\n",
        reinterpret_cast<void*>(scratch), reinterpret_cast<void*>(global),
        stored_global ? 1 : 0, stored_saved_rbx ? 1 : 0,
        static_cast<unsigned long>(libroblox_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(scratch);
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(scratch);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      g_start_app_with_params_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartAppLoggingHashBucketReadOffset &&
      instruction[0] == 0x41 && instruction[1] == 0x8b &&
      instruction[2] == 0x04 && instruction[3] == 0x99 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R9]) <
          kStage5LowAddressThreshold) {
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp logging hash table missing: returning "
          "miss rip_off=0x%lx table=%p r9=%p r10=%p key_index=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R10]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_R14] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppLoggingHashEmptyReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      g_start_app_with_params_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartAppLoggingHashWrapperBucketReadOffset &&
      instruction[0] == 0x23 && instruction[1] == 0x14 &&
      instruction[2] == 0xb1 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]) <
          kStage5LowAddressThreshold) {
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp logging hash wrapper missing: "
          "returning zero rip_off=0x%lx table=%p rcx=%p index=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppLoggingHashWrapperReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      g_start_app_with_params_recovery_in_progress != 0 &&
      libroblox_offset == kStage6StartAppLoggingHashCapacityReadOffset &&
      instruction[0] == 0x8b && instruction[1] == 0x54 &&
      instruction[2] == 0x96 && instruction[3] == 0x08 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]) <
          kStage5LowAddressThreshold) {
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp logging hash capacity missing: "
          "returning empty rip_off=0x%lx table=%p rsi=%p count=%p "
          "shift=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    ucontext->uc_mcontext.gregs[REG_RSI] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppLoggingHashCapacityReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kV2StartAppNullBucketTableReadOffset &&
      instruction[0] == 0x4a && instruction[1] == 0x8b &&
      instruction[2] == 0x04 && instruction[3] == 0xc8 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[360];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] nativeAppBridgeV2StartApp null bucket table: "
          "taking allocate path rip_off=0x%lx rbx=%p r9=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kV2StartAppNullBucketTableAllocateOffset);
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kV2StartAppLowBucketKeyReadOffset &&
      instruction[0] == 0x41 && instruction[1] == 0x8b &&
      instruction[2] == 0x04 && instruction[3] == 0x24 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]) <
          kStage5LowAddressThreshold) {
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[360];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] nativeAppBridgeV2StartApp low bucket key: "
          "using zero key rip_off=0x%lx r12=%p r14=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  if (g_current_stage >= 6 && info && instruction_readable &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]) <
          kStage5LowAddressThreshold &&
      instruction[0] == 0xf6 && instruction[1] == 0x06 &&
      instruction[2] == 0x01 && instruction[3] == 0x75 &&
      instruction[4] == 0x11 && instruction[5] == 0x48 &&
      instruction[6] == 0x8b && instruction[7] == 0x46 &&
      instruction[8] == 0x10) {
    if (g_stage6_gl_state_scratch_logs < 112) {
      char msg[640];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 textbox sync null string "
          "rip=%p off=0x%lx rdi=%p rsi=%p "
          "hint=mock GameTextInput State/string backing object\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x42;
    return;
  }
  if (g_current_stage >= 6 && info && libroblox_base == g_libroblox_base &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      (libroblox_offset == 0x6a90363 || libroblox_offset == 0x6a90366 ||
       libroblox_offset == 0x6a9041f)) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t slot_displacement =
        (libroblox_offset == 0x6a9041f) ? 0x20 : 0x28;
    if (rbp >= slot_displacement &&
        IsReadableMemoryRange(rbp - slot_displacement, sizeof(uintptr_t))) {
      auto* slot = reinterpret_cast<uintptr_t*>(rbp - slot_displacement);
      std::memset(g_stage5_fallback_region, 0, 0x40);
      *slot = reinterpret_cast<uintptr_t>(g_stage5_fallback_region);
      ucontext->uc_mcontext.gregs[REG_RAX] =
          reinterpret_cast<greg_t>(g_stage5_fallback_region);
      if (g_stage6_gl_state_scratch_logs < 80) {
        char msg[420];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] redirected Stage6 platform text bridge output slot "
            "off=0x%lx slot=%p scratch=%p\n",
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(slot),
            reinterpret_cast<void*>(g_stage5_fallback_region));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      return;
    }
  }
  if (g_current_stage >= 6 && info && g_libroblox_base != 0 &&
      instruction_address < kStage5LowAddressThreshold) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    uintptr_t return_address = 0;
    bool return_from_stack = false;
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      return_address = *reinterpret_cast<const uintptr_t*>(rsp);
      const uintptr_t return_offset =
          (return_address >= g_libroblox_base &&
           return_address < g_libroblox_base + 0x08000000)
              ? return_address - g_libroblox_base
              : 0;
      if (return_offset >= kLibrobloxTextStartOffset &&
          return_offset < kLibrobloxExecutableSegmentEndOffset &&
          IsExecutableMemoryRange(return_address, 1)) {
        return_from_stack = true;
      }
    }
    uintptr_t frame_rbp = 0;
    uintptr_t parent_return_address = 0;
    uintptr_t parent_return_offset = 0;
    if (!return_from_stack) {
      const uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      if (IsReadableMemoryRange(rbp, sizeof(uintptr_t) * 2)) {
        const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
        const uintptr_t frame_return_address = frame[1];
        const uintptr_t frame_return_offset =
            (frame_return_address >= g_libroblox_base &&
             frame_return_address < g_libroblox_base + 0x08000000)
                ? frame_return_address - g_libroblox_base
                : 0;
        if (frame_return_offset >= kLibrobloxTextStartOffset &&
            frame_return_offset < kLibrobloxExecutableSegmentEndOffset &&
            IsExecutableMemoryRange(frame_return_address, 1)) {
          return_address = frame_return_address;
          frame_rbp = frame[0];
          if (IsReadableMemoryRange(frame_rbp, sizeof(uintptr_t) * 2)) {
            const auto* parent_frame =
                reinterpret_cast<const uintptr_t*>(frame_rbp);
            parent_return_address = parent_frame[1];
            if (parent_return_address >= g_libroblox_base &&
                parent_return_address < g_libroblox_base + 0x08000000) {
              parent_return_offset = parent_return_address - g_libroblox_base;
            }
          }
        }
      }
    }
    if (return_address != 0) {
      const uintptr_t return_offset =
          (return_address >= g_libroblox_base &&
           return_address < g_libroblox_base + 0x08000000)
              ? return_address - g_libroblox_base
              : 0;
      bool restored_start_lua_string_frame = false;
      if (!return_from_stack && return_offset == 0x243ed8d) {
        const uintptr_t rbp =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
        if (rbp >= 0x28 && IsReadableMemoryRange(rbp - 0x28, 0x40)) {
          ucontext->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(
              *reinterpret_cast<const uintptr_t*>(rbp - 0x08));
          ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(
              *reinterpret_cast<const uintptr_t*>(rbp - 0x10));
          ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(
              *reinterpret_cast<const uintptr_t*>(rbp - 0x18));
          ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(
              *reinterpret_cast<const uintptr_t*>(rbp - 0x20));
          ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(
              *reinterpret_cast<const uintptr_t*>(rbp - 0x28));
          restored_start_lua_string_frame = true;
        }
      }
      if (!return_from_stack && instruction_address == 0x4 &&
          return_offset ==
              kStage6StartAppHashInsertExceptionFactoryReturnOffset &&
          parent_return_offset == kStage6StartAppHashInsertCallerReturnOffset &&
          (g_start_app_with_params_recovery_in_progress != 0 ||
           g_start_lua_app_dm_recovery_in_progress != 0) &&
          frame_rbp >= 0x28 && IsReadableMemoryRange(frame_rbp - 0x28, 0x38)) {
        std::memset(g_stage5_fallback_region, 0, 0x80);
        *reinterpret_cast<uint64_t*>(g_stage5_fallback_region + 0x08) =
            kStage6FakeIntrusiveRefcount;
        SeedStage6FakeIntrusiveRefcount(g_stage5_fallback_region,
                                        sizeof(g_stage5_fallback_region));
        ucontext->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x08));
        ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x10));
        ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x18));
        ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x20));
        ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x28));
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(parent_return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(frame_rbp + sizeof(uintptr_t) * 2);
        ucontext->uc_mcontext.gregs[REG_RBP] =
            static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(frame_rbp));
        ucontext->uc_mcontext.gregs[REG_RAX] =
            reinterpret_cast<greg_t>(g_stage5_fallback_region);
        if (g_stage6_gl_state_scratch_logs < 128) {
          char msg[640];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] unwound Stage6 StartApp hash-insert exception "
              "callback target=%p return_off=0x%lx "
              "parent_return_off=0x%lx scratch=%p frame=%p\n",
              reinterpret_cast<void*>(instruction_address),
              static_cast<unsigned long>(return_offset),
              static_cast<unsigned long>(parent_return_offset),
              reinterpret_cast<void*>(g_stage5_fallback_region),
              reinterpret_cast<void*>(frame_rbp));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        return;
      }
      if (!return_from_stack && instruction_address == 0x4 &&
          return_offset == kStage6StartGameMapHelperExceptionReturnOffset &&
          parent_return_offset == kStage6StartGameMapHelperCallerReturnOffset &&
          g_start_game_with_param_recovery_in_progress != 0 &&
          ShouldPatchStage6StartGameOwnerGameState() && frame_rbp >= 0x28 &&
          IsReadableMemoryRange(frame_rbp - 0x28, 0x38)) {
        const uintptr_t scratch = PrepareStage6StartGameMapEntryScratch(
            "unwind map helper exception");
        ucontext->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x08));
        ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x10));
        ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x18));
        ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x20));
        ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(frame_rbp - 0x28));
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(parent_return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(frame_rbp + sizeof(uintptr_t) * 2);
        ucontext->uc_mcontext.gregs[REG_RBP] =
            static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(frame_rbp));
        ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(scratch);
        if (g_stage6_gl_state_scratch_logs < 128) {
          char msg[720];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] unwound Stage6 StartGame map-helper exception "
              "callback target=%p return_off=0x%lx parent_return_off=0x%lx "
              "scratch=%p frame=%p\n",
              reinterpret_cast<void*>(instruction_address),
              static_cast<unsigned long>(return_offset),
              static_cast<unsigned long>(parent_return_offset),
              reinterpret_cast<void*>(scratch),
              reinterpret_cast<void*>(frame_rbp));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        return;
      }
      if (g_stage6_gl_state_scratch_logs < 128) {
        char msg[640];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 low-address callback target=%p "
            "return_off=0x%lx parent_return_off=0x%lx source=%s "
            "restored_regs=%s regs{rsp=%p rbp=%p rax=%p rdi=%p} "
            "hint=mock missing Java/platform callback target\n",
            reinterpret_cast<void*>(instruction_address),
            static_cast<unsigned long>(return_offset),
            static_cast<unsigned long>(parent_return_offset),
            return_from_stack ? "stack" : "frame",
            restored_start_lua_string_frame ? "startLuaString" : "none",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSP]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBP]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(return_address);
      if (return_from_stack) {
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rsp + sizeof(uintptr_t));
      } else {
        const uintptr_t rbp =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rbp + sizeof(uintptr_t) * 2);
        ucontext->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(frame_rbp);
      }
      ucontext->uc_mcontext.gregs[REG_RAX] =
          reinterpret_cast<greg_t>(g_stage5_fallback_region);
      return;
    }
  }
  const bool is_asset_path_callback_fault =
      libroblox_offset >= kStage6AssetPathNativeSetVtableCallOffset &&
      libroblox_offset <= kStage6AssetPathNativeSetVtableReturnOffset;
  const bool is_asset_path_callback_fallback_fault =
      libroblox_offset >= kStage6AssetPathNativeSetVtableCallFallbackOffset &&
      libroblox_offset <= kStage6AssetPathNativeSetVtableReturnFallbackOffset;
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_SET_ASSET_PATH_CALLBACK") && info &&
      (is_asset_path_callback_fault || is_asset_path_callback_fallback_fault) &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      (instruction[2] == 0x07 || instruction[2] == 0x03) &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    const uintptr_t return_offset =
        is_asset_path_callback_fallback_fault
            ? kStage6AssetPathNativeSetVtableReturnFallbackOffset
            : kStage6AssetPathNativeSetVtableReturnOffset;
    if (g_stage6_gl_state_scratch_logs < 96) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 MainGameActivity_nativeSetAssetPath vtable "
          "callback off=0x%lx si_addr=%p rip=%p "
          "hint=mock missing Java/platform callback target\n",
          static_cast<unsigned long>(libroblox_offset), info->si_addr,
          reinterpret_cast<void*>(instruction_address));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rbp >= sizeof(uintptr_t) * 2 &&
        IsReadableMemoryRange(rbp, sizeof(uintptr_t) * 2)) {
      const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
      const uintptr_t return_address = frame[1];
      if (IsLikelyUserPointer(return_address)) {
        ucontext->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(frame[0]);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rbp + sizeof(uintptr_t) * 2);
        ucontext->uc_mcontext.gregs[REG_RAX] = 0;
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        return;
      }
    }
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      const uintptr_t return_address = *reinterpret_cast<const uintptr_t*>(rsp);
      if (IsLikelyUserPointer(return_address)) {
        ucontext->uc_mcontext.gregs[REG_RAX] = 0;
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rsp + sizeof(uintptr_t));
        return;
      }
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(g_libroblox_base + return_offset);
    return;
  }
  if (g_current_stage >= 6 && info &&
      ucontext->uc_mcontext.gregs[REG_RIP] == 0 && g_libroblox_base != 0) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    if (rbp >= 0x20 && IsReadableMemoryRange(rbp - 0x20, 0x30)) {
      const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
      const uintptr_t return_address = frame[1];
      const uintptr_t return_offset = (return_address >= g_libroblox_base)
                                          ? return_address - g_libroblox_base
                                          : 0;
      if (return_offset == 0x42d4661) {
        if (g_stage6_gl_state_scratch_logs < 80) {
          char msg[640];
          int len =
              snprintf(msg, sizeof(msg),
                       "  [patch] returned empty object from Stage6 GL null "
                       "system-dialog callback return=%p rbp=%p "
                       "hint=mock NativeGLJavaInterface system-dialog callback "
                       "service\n",
                       reinterpret_cast<void*>(return_address),
                       reinterpret_cast<void*>(rbp));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        *reinterpret_cast<uintptr_t*>(g_stage5_fallback_region) = 0;
        ucontext->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(rbp - 0x08));
        ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(rbp - 0x10));
        ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(
            *reinterpret_cast<const uintptr_t*>(rbp - 0x18));
        ucontext->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(frame[0]);
        ucontext->uc_mcontext.gregs[REG_RSP] =
            static_cast<greg_t>(rbp + sizeof(uintptr_t) * 2);
        ucontext->uc_mcontext.gregs[REG_RAX] =
            reinterpret_cast<greg_t>(g_stage5_fallback_region);
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        return;
      }
    }
  }
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_SYSTEM_DIALOG_MESSAGE_NULL_RESULT") &&
      instruction_readable &&
      libroblox_offset == kStage6SystemDialogMessageNullResultReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x18 && info &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) <
          kStage5LowAddressThreshold) {
    if (g_stage6_gl_state_scratch_logs < 96) {
      char msg[560];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] substituted empty Stage6 system-dialog message object "
          "rip=%p off=0x%lx si_addr=%p rax=%p "
          "hint=mock NativeGLJavaInterface system-dialog message\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset), info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    *reinterpret_cast<uintptr_t*>(g_stage5_fallback_region) = 0;
    SeedStage6FakeIntrusiveRefcount(g_stage5_fallback_region,
                                    sizeof(g_stage5_fallback_region));
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  const bool is_stage6_start_lua_first_null_callback =
      libroblox_offset == kStage6StartLuaNullCallbackReadOffset;
  const bool is_stage6_start_lua_self_ref_null_callback =
      libroblox_offset == kStage6StartLuaSelfReferenceNullCallbackReadOffset;
  const bool is_stage6_start_lua_second_null_callback =
      libroblox_offset == kStage6StartLuaSecondNullCallbackReadOffset;
  const bool is_stage6_start_lua_first_callback_site =
      is_stage6_start_lua_first_null_callback ||
      is_stage6_start_lua_self_ref_null_callback;
  if (g_current_stage >= 6 &&
      !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NULL_CALLBACK") &&
      instruction_readable &&
      (is_stage6_start_lua_first_callback_site ||
       is_stage6_start_lua_second_null_callback) &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x07 && info &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) <
          kStage5LowAddressThreshold) {
    const uintptr_t start_lua_owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t start_lua_payload = static_cast<uintptr_t>(
        ucontext->uc_mcontext
            .gregs[is_stage6_start_lua_first_callback_site ? REG_R14
                                                           : REG_RSI]);
    const uintptr_t start_lua_result = static_cast<uintptr_t>(
        ucontext->uc_mcontext
            .gregs[is_stage6_start_lua_first_callback_site ? REG_R15
                                                           : REG_R14]);
    uintptr_t start_lua_state = 0;
    uint32_t start_lua_phase = 0xffffffffu;
    uint64_t start_lua_payload_first = 0;
    const uintptr_t slot_028 = ReadPointerIfReadable(start_lua_owner + 0x28);
    const uintptr_t slot_030 = ReadPointerIfReadable(start_lua_owner + 0x30);
    const uintptr_t slot_038 = ReadPointerIfReadable(start_lua_owner + 0x38);
    const uintptr_t slot_118 = ReadPointerIfReadable(start_lua_owner + 0x118);
    const uintptr_t slot_248 = ReadPointerIfReadable(start_lua_owner + 0x248);
    const uintptr_t slot_3f8 = ReadPointerIfReadable(start_lua_owner + 0x3f8);
    const uintptr_t slot_400 = ReadPointerIfReadable(start_lua_owner + 0x400);
    const uintptr_t slot_408 = ReadPointerIfReadable(start_lua_owner + 0x408);
    const uintptr_t slot_410 = ReadPointerIfReadable(start_lua_owner + 0x410);
    const uintptr_t slot_418 = ReadPointerIfReadable(start_lua_owner + 0x418);
    const uintptr_t slot_420 = ReadPointerIfReadable(start_lua_owner + 0x420);
    const uintptr_t configured_anchor_slot =
        GetEnvAddress("MOCKTAIL_STAGE6_START_LUA_STATE_ANCHOR_SLOT", 0);
    uintptr_t configured_anchor = 0;
    if (configured_anchor_slot > 0 && configured_anchor_slot < 0x800) {
      configured_anchor =
          ReadPointerIfReadable(start_lua_owner + configured_anchor_slot);
    }
    const uintptr_t configured_anchor_008 =
        ReadPointerIfReadable(configured_anchor + 0x08);
    const uintptr_t configured_anchor_010 =
        ReadPointerIfReadable(configured_anchor + 0x10);
    const uintptr_t configured_anchor_020 =
        ReadPointerIfReadable(configured_anchor + 0x20);
    uintptr_t caller = 0;
    uintptr_t grandcaller = 0;
    const uintptr_t frame =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    if (IsReadableMemoryRange(frame + sizeof(uintptr_t), sizeof(uintptr_t))) {
      caller = *reinterpret_cast<const uintptr_t*>(frame + sizeof(uintptr_t));
    }
    const uintptr_t caller_frame = ReadPointerIfReadable(frame);
    if (IsReadableMemoryRange(caller_frame + sizeof(uintptr_t),
                              sizeof(uintptr_t))) {
      grandcaller =
          *reinterpret_cast<const uintptr_t*>(caller_frame + sizeof(uintptr_t));
    }
    const uintptr_t caller_offset =
        (caller >= libroblox_base) ? caller - libroblox_base : 0;
    const uintptr_t grandcaller_offset =
        (grandcaller >= libroblox_base) ? grandcaller - libroblox_base : 0;
    if (IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_OWNER")) {
      static volatile sig_atomic_t owner_trace_logs = 0;
      if (owner_trace_logs < 24) {
        ++owner_trace_logs;
        const uintptr_t reg_rdi =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
        const uintptr_t reg_rsi =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
        const uintptr_t reg_rdx =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
        const uintptr_t reg_rcx =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
        const uintptr_t reg_r8 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R8]);
        const uintptr_t reg_r9 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R9]);
        const uintptr_t reg_r12 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
        const uintptr_t reg_r13 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
        const uintptr_t reg_r14 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
        const uintptr_t reg_r15 =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
        const uintptr_t reg_rsp =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
        const uintptr_t reg_rbp =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
        char msg[2800];
        int len = snprintf(
            msg, sizeof(msg),
            "  [trace] Stage6 StartLua owner snapshot "
            "site=%d rip=%p off=0x%lx caller_off=0x%lx "
            "grandcaller_off=0x%lx si_addr=%p "
            "regs{rdi=%p rsi=%p rdx=%p rcx=%p r8=%p r9=%p "
            "r12=%p r13=%p r14=%p r15=%p rsp=%p rbp=%p} "
            "owner=%p slots{28=%p 30=%p 38=%p 118=%p 248=%p "
            "3f8=%p 400=%p 408=%p 410=%p 418=%p 420=%p} "
            "owner_tables{0=%p/%p 1=%p/%p 2=%p/%p 3=%p/%p} "
            "rdx_obj{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p} "
            "payload=%p payload_fields{0=%p 8=%p 10=%p 18=%p} "
            "result=%p result_fields{0=%p 8=%p 10=%p 18=%p}\n",
            is_stage6_start_lua_second_null_callback     ? 2
            : is_stage6_start_lua_self_ref_null_callback ? 11
                                                         : 1,
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            static_cast<unsigned long>(libroblox_offset),
            static_cast<unsigned long>(caller_offset),
            static_cast<unsigned long>(grandcaller_offset), info->si_addr,
            reinterpret_cast<void*>(reg_rdi), reinterpret_cast<void*>(reg_rsi),
            reinterpret_cast<void*>(reg_rdx), reinterpret_cast<void*>(reg_rcx),
            reinterpret_cast<void*>(reg_r8), reinterpret_cast<void*>(reg_r9),
            reinterpret_cast<void*>(reg_r12), reinterpret_cast<void*>(reg_r13),
            reinterpret_cast<void*>(reg_r14), reinterpret_cast<void*>(reg_r15),
            reinterpret_cast<void*>(reg_rsp), reinterpret_cast<void*>(reg_rbp),
            reinterpret_cast<void*>(start_lua_owner),
            reinterpret_cast<void*>(slot_028),
            reinterpret_cast<void*>(slot_030),
            reinterpret_cast<void*>(slot_038),
            reinterpret_cast<void*>(slot_118),
            reinterpret_cast<void*>(slot_248),
            reinterpret_cast<void*>(slot_3f8),
            reinterpret_cast<void*>(slot_400),
            reinterpret_cast<void*>(slot_408),
            reinterpret_cast<void*>(slot_410),
            reinterpret_cast<void*>(slot_418),
            reinterpret_cast<void*>(slot_420),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x850)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x858)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x860)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x868)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x870)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x878)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x880)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_owner + 0x888)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x08)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x10)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x18)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x20)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x28)),
            reinterpret_cast<void*>(ReadPointerIfReadable(reg_rdx + 0x30)),
            reinterpret_cast<void*>(start_lua_payload),
            reinterpret_cast<void*>(ReadPointerIfReadable(start_lua_payload)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_payload + 0x08)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_payload + 0x10)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_payload + 0x18)),
            reinterpret_cast<void*>(start_lua_result),
            reinterpret_cast<void*>(ReadPointerIfReadable(start_lua_result)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_result + 0x08)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_result + 0x10)),
            reinterpret_cast<void*>(
                ReadPointerIfReadable(start_lua_result + 0x18)));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
      }
    }
    if (is_stage6_start_lua_first_callback_site &&
        caller_offset == kStage6StartLuaDirectClosureEarlySetupReturnOffset &&
        !IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_FALLBACK_CALLBACK_TARGET") &&
        !IsDisabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_SKIP_EARLY_SETUP_NULL_CALLBACK")) {
      if (g_stage6_gl_state_scratch_logs < 112) {
        char msg[900];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped Stage6 StartLua early setup null callback "
            "rip=%p off=0x%lx caller_off=0x%lx owner=%p "
            "slots{28=%p 30=%p 38=%p 118=%p 248=%p 3f8=%p 418=%p} "
            "hint=continue direct closure to logged-in branch\n",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            static_cast<unsigned long>(libroblox_offset),
            static_cast<unsigned long>(caller_offset),
            reinterpret_cast<void*>(start_lua_owner),
            reinterpret_cast<void*>(slot_028),
            reinterpret_cast<void*>(slot_030),
            reinterpret_cast<void*>(slot_038),
            reinterpret_cast<void*>(slot_118),
            reinterpret_cast<void*>(slot_248),
            reinterpret_cast<void*>(slot_3f8),
            reinterpret_cast<void*>(slot_418));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      if (UnwindStage6StartLuaSetupFrame(ucontext)) {
        ++g_skipped_headless_null_writes;
        return;
      }
    }
    if (slot_3f8 == 0) {
      const uintptr_t fallback_callback_target =
          InstallStage6StartLuaFallbackCallbackTarget(
              start_lua_owner, is_stage6_start_lua_self_ref_null_callback
                                   ? "self-ref-null-callback"
                               : is_stage6_start_lua_first_null_callback
                                   ? "first-null-callback"
                                   : "second-null-callback");
      if (fallback_callback_target != 0) {
        InstallStage6StartLuaFallbackState(
            start_lua_owner, configured_anchor,
            is_stage6_start_lua_self_ref_null_callback
                ? "self-ref-null-callback"
            : is_stage6_start_lua_first_null_callback ? "first-null-callback"
                                                      : "second-null-callback");
        SeedStage6StartLuaPrimaryStateFromOwner(
            start_lua_owner, is_stage6_start_lua_self_ref_null_callback
                                 ? "self-ref-null-callback"
                             : is_stage6_start_lua_first_null_callback
                                 ? "first-null-callback"
                                 : "second-null-callback");
        ucontext->uc_mcontext.gregs[REG_RDI] =
            static_cast<greg_t>(fallback_callback_target);
        if (g_stage6_gl_state_scratch_logs < 112) {
          char msg[520];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] retrying Stage6 StartLua null callback with "
              "fallback target site=%d rip=%p off=0x%lx owner=%p target=%p\n",
              is_stage6_start_lua_second_null_callback     ? 2
              : is_stage6_start_lua_self_ref_null_callback ? 11
                                                           : 1,
              reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
              static_cast<unsigned long>(libroblox_offset),
              reinterpret_cast<void*>(start_lua_owner),
              reinterpret_cast<void*>(fallback_callback_target));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        return;
      }
    }
    const bool start_lua_state_slot_readable =
        IsReadableMemoryRange(start_lua_owner + 0x418, sizeof(uintptr_t));
    bool substituted_start_lua_state = false;
    if (start_lua_state_slot_readable) {
      start_lua_state = slot_418;
    }
    if (start_lua_state == 0 && start_lua_state_slot_readable &&
        !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NULL_STATE")) {
      std::memset(g_stage6_start_lua_state_scratch, 0,
                  sizeof(g_stage6_start_lua_state_scratch));
      std::memset(g_stage6_start_lua_anchor_scratch, 0,
                  sizeof(g_stage6_start_lua_anchor_scratch));
      std::memset(g_stage6_start_lua_callback_scratch, 0,
                  sizeof(g_stage6_start_lua_callback_scratch));
      SeedStage6FakeIntrusiveRefcount(
          g_stage6_start_lua_callback_scratch,
          sizeof(g_stage6_start_lua_callback_scratch));
      *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch) = 1;
      *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch + 0x10) =
          0x7fffffffu;
      *reinterpret_cast<uint32_t*>(g_stage6_start_lua_callback_scratch) = 1;
      *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_anchor_scratch + 0x08) =
          reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_scratch);
      *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_callback_scratch +
                                    0x08) =
          reinterpret_cast<uintptr_t>(
              &mocktail_stage6_start_lua_noop_continuation);
      *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_state_scratch) =
          configured_anchor != 0
              ? configured_anchor
              : reinterpret_cast<uintptr_t>(g_stage6_start_lua_anchor_scratch);
      *reinterpret_cast<uint32_t*>(g_stage6_start_lua_state_scratch + 0x138) =
          0;
      start_lua_state =
          reinterpret_cast<uintptr_t>(g_stage6_start_lua_state_scratch);
      *reinterpret_cast<uintptr_t*>(start_lua_owner + 0x418) = start_lua_state;
      substituted_start_lua_state = true;
    }
    if (IsReadableMemoryRange(start_lua_state + 0x138, sizeof(uint32_t))) {
      start_lua_phase =
          *reinterpret_cast<const uint32_t*>(start_lua_state + 0x138);
    }
    if (IsReadableMemoryRange(start_lua_payload, sizeof(uint64_t))) {
      start_lua_payload_first =
          *reinterpret_cast<const uint64_t*>(start_lua_payload);
    }
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER") &&
        g_libroblox_base != 0) {
      auto resolve_owner_source = [&](const char* name,
                                      uintptr_t default_offset,
                                      uintptr_t* source_offset) -> uintptr_t {
        const char* value = std::getenv(name);
        if (value != nullptr && std::strcmp(value, "owner") == 0) {
          *source_offset = static_cast<uintptr_t>(-1);
          return start_lua_owner;
        }
        const uintptr_t offset = GetEnvAddress(name, default_offset);
        *source_offset = offset;
        if (offset < 0x1000) {
          return ReadPointerIfReadable(start_lua_owner + offset);
        }
        return offset;
      };
      uintptr_t primary_slot_8_source = 0;
      uintptr_t primary_slot_10_source = 0;
      uintptr_t primary_slot_18_source = 0;
      const uintptr_t primary_slot_8 =
          resolve_owner_source("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT8_SOURCE",
                               0x28, &primary_slot_8_source);
      const uintptr_t primary_slot_10 = resolve_owner_source(
          "MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT10_SOURCE", 0x30,
          &primary_slot_10_source);
      const uintptr_t primary_slot_18 = resolve_owner_source(
          "MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT18_SOURCE", 0x38,
          &primary_slot_18_source);
      if (primary_slot_8 != 0 && primary_slot_10 != 0) {
        g_stage6_start_lua_owner_slot_028 = primary_slot_8;
        g_stage6_start_lua_owner_slot_030 = primary_slot_10;
        g_stage6_start_lua_owner_slot_038 = primary_slot_18;
      }
      const uintptr_t primary =
          g_libroblox_base + kStage6AppBridgePrimaryStateOffset;
      if (primary_slot_8 != 0 && primary_slot_10 != 0 &&
          IsReadableMemoryRange(primary, 0x20) &&
          EnsureWritablePage(reinterpret_cast<void*>(primary))) {
        *reinterpret_cast<uintptr_t*>(primary + 0x08) = primary_slot_8;
        *reinterpret_cast<uintptr_t*>(primary + 0x10) = primary_slot_10;
        *reinterpret_cast<uintptr_t*>(primary + 0x18) = primary_slot_18;
        if (g_stage6_gl_state_scratch_logs < 112) {
          char patch_msg[1300];
          int patch_len = snprintf(
              patch_msg, sizeof(patch_msg),
              "  [patch] Stage6 StartLua primary state seeded from owner "
              "primary=%p source{8=0x%lx 10=0x%lx 18=0x%lx} "
              "fields{8=%p 10=%p 18=%p} "
              "candidates{owner_t0=%p/%p owner_t1=%p/%p "
              "slot28_t0=%p/%p slot28_t1=%p/%p "
              "slot30_t0=%p/%p slot30_t1=%p/%p "
              "slot38_t0=%p/%p slot38_t1=%p/%p}\n",
              reinterpret_cast<void*>(primary),
              static_cast<unsigned long>(primary_slot_8_source),
              static_cast<unsigned long>(primary_slot_10_source),
              static_cast<unsigned long>(primary_slot_18_source),
              reinterpret_cast<void*>(primary_slot_8),
              reinterpret_cast<void*>(primary_slot_10),
              reinterpret_cast<void*>(primary_slot_18),
              reinterpret_cast<void*>(
                  ReadPointerIfReadable(start_lua_owner + 0x850)),
              reinterpret_cast<void*>(
                  ReadPointerIfReadable(start_lua_owner + 0x858)),
              reinterpret_cast<void*>(
                  ReadPointerIfReadable(start_lua_owner + 0x860)),
              reinterpret_cast<void*>(
                  ReadPointerIfReadable(start_lua_owner + 0x868)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_028 + 0x850)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_028 + 0x858)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_028 + 0x860)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_028 + 0x868)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_030 + 0x850)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_030 + 0x858)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_030 + 0x860)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_030 + 0x868)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_038 + 0x850)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_038 + 0x858)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_038 + 0x860)),
              reinterpret_cast<void*>(ReadPointerIfReadable(slot_038 + 0x868)));
          if (patch_len > 0) {
            write(2, patch_msg, static_cast<size_t>(patch_len));
          }
        }
      }
    }
    if (g_stage6_gl_state_scratch_logs < 112) {
      char msg[1900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 StartLua null callback "
          "site=%d rip=%p off=0x%lx caller_off=0x%lx "
          "grandcaller_off=0x%lx si_addr=%p rdi=%p owner=%p "
          "cb=%p slots{28=%p 30=%p 38=%p 118=%p 248=%p "
          "3f8=%p 400=%p 408=%p 410=%p 418=%p 420=%p} "
          "state=%p anchor_slot=0x%lx anchor=%p "
          "anchor_fields{8=%p 10=%p 20=%p} "
          "phase=0x%x state_sub=%d "
          "arg=%p arg0=0x%llx result=%p "
          "hint=mock missing lifecycle callback target\n",
          is_stage6_start_lua_second_null_callback     ? 2
          : is_stage6_start_lua_self_ref_null_callback ? 11
                                                       : 1,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          static_cast<unsigned long>(caller_offset),
          static_cast<unsigned long>(grandcaller_offset), info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(start_lua_owner),
          reinterpret_cast<void*>(slot_3f8), reinterpret_cast<void*>(slot_028),
          reinterpret_cast<void*>(slot_030), reinterpret_cast<void*>(slot_038),
          reinterpret_cast<void*>(slot_118), reinterpret_cast<void*>(slot_248),
          reinterpret_cast<void*>(slot_3f8), reinterpret_cast<void*>(slot_400),
          reinterpret_cast<void*>(slot_408), reinterpret_cast<void*>(slot_410),
          reinterpret_cast<void*>(slot_418), reinterpret_cast<void*>(slot_420),
          reinterpret_cast<void*>(start_lua_state),
          static_cast<unsigned long>(configured_anchor_slot),
          reinterpret_cast<void*>(configured_anchor),
          reinterpret_cast<void*>(configured_anchor_008),
          reinterpret_cast<void*>(configured_anchor_010),
          reinterpret_cast<void*>(configured_anchor_020), start_lua_phase,
          substituted_start_lua_state ? 1 : 0,
          reinterpret_cast<void*>(start_lua_payload),
          static_cast<unsigned long long>(start_lua_payload_first),
          reinterpret_cast<void*>(start_lua_result));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        g_libroblox_base + (is_stage6_start_lua_first_callback_site
                                ? kStage6StartLuaCallbackCleanupOffset
                                : kStage6StartLuaSecondCallbackCleanupOffset));
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset >= kStage6GlUnsupportedObjectReadStartOffset &&
      libroblox_offset <= kStage6GlUnsupportedObjectReadEndOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      (instruction[2] == 0x00 || instruction[2] == 0x07) &&
      instruction[3] == 0x48 && instruction[4] == 0xbb &&
      instruction[5] == 0xff && instruction[6] == 0xff &&
      instruction[7] == 0xff && instruction[8] == 0xff &&
      instruction[9] == 0xff && instruction[10] == 0xff &&
      instruction[11] == 0x00 && instruction[12] == 0x00 &&
      instruction[13] == 0x48 && instruction[14] == 0x21 &&
      instruction[15] == 0xc3 && info) {
    const int object_reg = instruction[2] == 0x00 ? REG_RAX : REG_RDI;
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[object_reg]);
    if (!IsReadableMemoryRange(object, sizeof(uintptr_t))) {
      if (g_stage6_gl_state_scratch_logs < 64) {
        char msg[720];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] returned false from Stage6 GL unsupported-message "
            "helper with invalid object rip=%p off=0x%lx si_addr=%p "
            "reg=%s object=%p rbp=%p "
            "hint=mock NativeGLJavaInterface platform-message object/service\n",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            static_cast<unsigned long>(libroblox_offset), info->si_addr,
            object_reg == REG_RAX ? "rax" : "rdi",
            reinterpret_cast<void*>(object),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBP]));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      ++g_skipped_headless_null_writes;
      if (TryReturnFromDecodedRbpFrame(ucontext, instruction, libroblox_base,
                                       0)) {
        return;
      }
    }
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset >= kStage6GlUnsupportedObjectReadStartOffset &&
      libroblox_offset <= kStage6GlUnsupportedObjectReadEndOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x87 &&
      instruction[3] == 0x48) {
    const int base_reg = instruction[2] == 0x43   ? REG_RBX
                         : instruction[2] == 0x48 ? REG_RAX
                                                  : -1;
    const int old_value_reg = instruction[2] == 0x43   ? REG_RAX
                              : instruction[2] == 0x48 ? REG_RCX
                                                       : -1;
    if (base_reg >= 0 && old_value_reg >= 0) {
      const uintptr_t base_value =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[base_reg]);
      if (!IsReadableMemoryRange(base_value + 0x48, sizeof(uintptr_t))) {
        if (g_stage6_gl_state_scratch_logs < 96) {
          char msg[420];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] skipped Stage6 GL invalid object atomic exchange "
              "off=0x%lx object=%p\n",
              static_cast<unsigned long>(libroblox_offset),
              reinterpret_cast<void*>(base_value));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_stage6_gl_state_scratch_logs;
        }
        ++g_skipped_headless_null_writes;
        ucontext->uc_mcontext.gregs[old_value_reg] = 0;
        ucontext->uc_mcontext.gregs[REG_RIP] += 4;
        return;
      }
    }
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6ProtectedTableEntryReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x7c && instruction[3] == 0xc1 &&
      instruction[4] == 0x08 && info) {
    if (g_skipped_headless_null_writes < 64) {
      char msg[360];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] treated Stage6 protected table entry as empty "
          "rip=%p off=0x%lx si_addr=%p rcx=%p rax=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset), info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 5;
    return;
  }
  if (g_current_stage >= 6 && instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kAppStartSchedulerFaultOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x83 &&
      instruction[2] == 0xbf && instruction[3] == 0x98 &&
      instruction[4] == 0x00 && instruction[5] == 0x00 &&
      instruction[6] == 0x00 && instruction[7] == 0x00) {
    const uintptr_t rdi =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    if (!IsLikelyUserPointer(rdi)) {
      void* resolved = ResolveRobloxTaggedPointer(rdi, libroblox_base);
      if (resolved != nullptr) {
        if (g_appstart_scheduler_guard_logs < 8) {
          char msg[360];
          int len = snprintf(msg, sizeof(msg),
                             "  [patch] nativeAppBridgeAppStart scheduler ref: "
                             "handle=%p -> object=%p rip_off=0x%lx\n",
                             reinterpret_cast<void*>(rdi), resolved,
                             static_cast<unsigned long>(libroblox_offset));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_appstart_scheduler_guard_logs;
        }
        ucontext->uc_mcontext.gregs[REG_RDI] =
            reinterpret_cast<greg_t>(resolved);
        return;
      }
      if (g_appstart_scheduler_guard_logs < 8) {
        char msg[360];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] nativeAppBridgeAppStart scheduler guard: "
            "unresolved object=%p rip_off=0x%lx game_activity=%p\n",
            reinterpret_cast<void*>(rdi),
            static_cast<unsigned long>(libroblox_offset),
            reinterpret_cast<void*>(
                static_cast<uintptr_t>(g_game_activity_native_handle)));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_appstart_scheduler_guard_logs;
      }
    }
  }
  if (g_current_stage >= 6 && instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kAppStartCleanupFaultOffset &&
      instruction[0] == 0x83 && instruction[1] == 0xbb &&
      instruction[2] == 0x40 && instruction[3] == 0x01 &&
      instruction[4] == 0x00 && instruction[5] == 0x00 &&
      instruction[6] == 0x00) {
    const uintptr_t rbx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    if (!IsLikelyUserPointer(rbx)) {
      void* resolved = ResolveRobloxTaggedPointer(rbx, libroblox_base);
      if (resolved != nullptr) {
        if (g_appstart_cleanup_guard_logs < 8) {
          char msg[360];
          int len = snprintf(msg, sizeof(msg),
                             "  [patch] nativeAppBridgeAppStart cleanup ref: "
                             "handle=%p -> object=%p rip_off=0x%lx\n",
                             reinterpret_cast<void*>(rbx), resolved,
                             static_cast<unsigned long>(libroblox_offset));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ++g_appstart_cleanup_guard_logs;
        }
        ucontext->uc_mcontext.gregs[REG_RBX] =
            reinterpret_cast<greg_t>(resolved);
        return;
      }
      if (g_appstart_cleanup_guard_logs < 8) {
        char msg[360];
        int len = snprintf(msg, sizeof(msg),
                           "  [patch] nativeAppBridgeAppStart cleanup guard: "
                           "unresolved object=%p rip_off=0x%lx\n",
                           reinterpret_cast<void*>(rbx),
                           static_cast<unsigned long>(libroblox_offset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_appstart_cleanup_guard_logs;
      }
    }
  }
  if (g_current_stage >= 6 && libroblox_offset == 0x1f2436b &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x10) {
    const char msg[] =
        "  [patch] redirected Roblox allocator TLS fast-path to slow path\n";
    write(2, msg, sizeof(msg) - 1);
    ucontext->uc_mcontext.gregs[REG_RSI] = ucontext->uc_mcontext.gregs[REG_RBX];
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x12;
    return;
  }

  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kV2StartAppNullManagerOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x78 && instruction[3] == 0x18 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    ResetStartAppManagerScratch();
    if (g_start_app_null_manager_guard_logs < 8) {
      char msg[320];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [patch] nativeAppBridgeV2StartApp null manager read: "
                   "using scratch object=%p rip_off=0x%lx\n",
                   reinterpret_cast<void*>(g_start_app_manager_scratch),
                   static_cast<unsigned long>(libroblox_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_null_manager_guard_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(g_start_app_manager_scratch);
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kV2StartAppManagerOutWriteOffset &&
      instruction[0] == 0x49 && instruction[1] == 0x89 &&
      instruction[2] == 0x46 && instruction[3] == 0x10 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      ucontext->uc_mcontext.gregs[REG_R14] == 0) {
    ResetStartAppManagerScratch();
    if (g_start_app_manager_scratch_logs < 8) {
      char msg[320];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [patch] nativeAppBridgeV2StartApp manager out-object: "
                   "redirecting r14 to scratch object=%p rip_off=0x%lx\n",
                   reinterpret_cast<void*>(g_start_app_manager_scratch),
                   static_cast<unsigned long>(libroblox_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_start_app_manager_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] =
        reinterpret_cast<greg_t>(g_start_app_manager_scratch);
    return;
  }

  if (g_current_stage >= 6 && g_stage6_jni_env != 0 &&
      reinterpret_cast<uintptr_t>(instruction) == g_stage6_jni_env) {
    uintptr_t return_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    auto* return_addr = reinterpret_cast<uintptr_t*>(return_slot);
    char msg[512];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] skipped erroneous Stage6 call through JNIEnv pointer "
        "ret=%p rsp=%p rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p r8=%p r9=%p\n",
        return_addr ? reinterpret_cast<void*>(*return_addr) : nullptr,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSP]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    if (return_addr != nullptr && *return_addr != 0) {
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(*return_addr);
      ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      return;
    }
  }

  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6LinkedListLowWriteOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x89 &&
      instruction[2] == 0x19 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    if (g_stage6_linked_list_low_write_logs < 12) {
      char msg[420];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped Stage6 linked-list low write "
          "rip=%p off=0x%lx si_addr=%p rax=%p rbx=%p rcx=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset), info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_linked_list_low_write_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  const bool is_gl_state_read_rdx =
      (libroblox_offset == kStage6GlStateReadOffset ||
       libroblox_offset == kStage6GlStateReadAltOffset) &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x50 && instruction[3] == 0x70;
  const bool is_gl_state_read_r15 =
      libroblox_offset == kStage6GlStateReadR15Offset &&
      instruction[0] == 0x4c && instruction[1] == 0x8b &&
      instruction[2] == 0x78 && instruction[3] == 0x70;
  const bool is_gl_state_read_rdi =
      libroblox_offset == kStage6GlStateReadRdiOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x78 && instruction[3] == 0x70;
  const bool is_gl_queue_read_rax =
      libroblox_offset == kStage6GlQueueReadOffset && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x40 &&
      instruction[3] == 0x68;
  const bool is_gl_state_flag_read_eax =
      libroblox_offset == kStage6GlStateFlagReadOffset &&
      instruction[0] == 0x8b && instruction[1] == 0x40 &&
      instruction[2] == 0x20;
  const bool is_gl_counter_read =
      libroblox_offset == kStage6GlCounterReadOffset &&
      instruction[0] == 0x83 && instruction[1] == 0x38 &&
      instruction[2] == 0x00;
  const bool is_gl_queue_self_compare =
      libroblox_offset == kStage6GlQueueSelfCompareOffset &&
      g_game_global_init_recovery_in_progress == 0 && instruction[0] == 0x48 &&
      instruction[1] == 0x39 && instruction[2] == 0x76 &&
      instruction[3] == 0x68;
  if (g_current_stage >= 6 && instruction_readable &&
      (libroblox_offset == kStage6GlWaitBeginCallbackReadOffset ||
       libroblox_offset == kStage6GlWaitEndCallbackReadOffset) &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x42 && instruction[3] == 0x28 &&
      ucontext->uc_mcontext.gregs[REG_RDX] == 0) {
    uintptr_t return_offset =
        libroblox_offset == kStage6GlWaitBeginCallbackReadOffset
            ? kStage6GlWaitBeginCallbackSkipOffset
            : kStage6GlWaitEndCallbackSkipOffset;
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[420];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped null Stage6 GL wait callback table "
          "rip=%p off=0x%lx return_off=0x%lx\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          static_cast<unsigned long>(return_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(base + return_offset);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlTlsQueueNullWriteOffset &&
      instruction[0] == 0x49 && instruction[1] == 0xc7 &&
      instruction[2] == 0x44 && instruction[3] == 0x24 &&
      instruction[4] == 0x58 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    uintptr_t tls =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    if (IsReadableMemoryRange(tls + 0x410, sizeof(uint64_t))) {
      *reinterpret_cast<uint64_t*>(tls + 0x3f0) = 0;
      *reinterpret_cast<uint64_t*>(tls + 0x400) = static_cast<uint64_t>(state);
      *reinterpret_cast<uint64_t*>(tls + 0x408) = static_cast<uint64_t>(queue);
      *reinterpret_cast<uint64_t*>(tls + 0x410) = static_cast<uint64_t>(queue);
    }
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] initialized Stage6 GL TLS queue "
          "rip=%p off=0x%lx tls=%p queue=%p state=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(tls), reinterpret_cast<void*>(queue),
          reinterpret_cast<void*>(state));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(queue);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlTlsStateNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x58 && instruction[3] == 0x08 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    uintptr_t tls =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    if (tls >= kStage5LowAddressThreshold && tls < kMaxCanonicalUserPointer) {
      *reinterpret_cast<uint64_t*>(tls + 0x3f0) = 0;
      *reinterpret_cast<uint64_t*>(tls + 0x400) = static_cast<uint64_t>(state);
      *reinterpret_cast<uint64_t*>(tls + 0x408) = static_cast<uint64_t>(queue);
      *reinterpret_cast<uint64_t*>(tls + 0x410) = static_cast<uint64_t>(queue);
    }
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] initialized Stage6 GL TLS state "
          "rip=%p off=0x%lx tls=%p state=%p queue=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(tls), reinterpret_cast<void*>(state),
          reinterpret_cast<void*>(queue));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(state);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlTlsReturnedQueueNullOffset &&
      instruction[0] == 0x49 && instruction[1] == 0x83 &&
      instruction[2] == 0x4d && instruction[3] == 0x20 &&
      reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr) <
          kStage5LowAddressThreshold) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    uintptr_t tls_plus_queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    uintptr_t tls = tls_plus_queue >= 0x410 ? tls_plus_queue - 0x410 : 0;
    if (tls >= kStage5LowAddressThreshold && tls < kMaxCanonicalUserPointer) {
      *reinterpret_cast<uint64_t*>(tls + 0x3f0) = 0;
      *reinterpret_cast<uint64_t*>(tls + 0x400) = static_cast<uint64_t>(state);
      *reinterpret_cast<uint64_t*>(tls + 0x408) = static_cast<uint64_t>(queue);
      *reinterpret_cast<uint64_t*>(tls + 0x410) = static_cast<uint64_t>(queue);
    }
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[500];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] restored Stage6 GL returned queue "
          "rip=%p off=0x%lx tls=%p state=%p queue=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(tls), reinterpret_cast<void*>(state),
          reinterpret_cast<void*>(queue));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(queue);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlQueueAtomicLowReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x01 &&
      reinterpret_cast<uintptr_t>(info ? info->si_addr : nullptr) <
          kStage6LikelyHostPointerThreshold) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    uintptr_t queue_atomic = scratch + 0x1a40;
    *reinterpret_cast<uint64_t*>(queue_atomic) = 0;
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] redirected Stage6 GL queue atomic "
          "rip=%p off=0x%lx old_rcx=%p state=%p queue=%p cell=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
          reinterpret_cast<void*>(state), reinterpret_cast<void*>(queue),
          reinterpret_cast<void*>(queue_atomic));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RCX] = static_cast<greg_t>(queue_atomic);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlEventQueueNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x40 && instruction[3] == 0x68 &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    if (g_stage6_gl_state_scratch_logs < 48) {
      char msg[420];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] restored Stage6 GL event queue "
          "rip=%p off=0x%lx state=%p queue=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(state), reinterpret_cast<void*>(queue));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(queue);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset == kStage6GlQueueCallbackTailRetOffset &&
      instruction[0] == 0xc3 && ucontext->uc_mcontext.gregs[REG_RSP] == 0) {
    if (g_stage6_gl_state_scratch_logs < 48) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] recovered Stage6 GL callback tail with null stack "
          "rip=%p off=0x%lx rbp=%p rax=%p rsi=%p rdi=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBP]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_stage6_empty_gl_helper_returns;
    if (g_game_global_init_recovery_in_progress != 0) {
      g_game_global_init_recovery_in_progress = 0;
      const char msg[] =
          "  [patch] recovered nativeGameGlobalInit after null-stack Stage6 GL "
          "callback tail\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_game_global_init_jmp_buf, 1);
      return;
    }
    if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
        g_start_lua_app_dm_recovery_in_progress == kStage6RecoveryWorker) {
      g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] exiting worker after null-stack Stage6 GL callback tail "
          "in nativeAppBridgeStartLuaAppDM\n";
      write(2, msg, sizeof(msg) - 1);
      ExitCurrentThreadImmediately();
    }
    if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
        g_update_surface_app_recovery_in_progress == kStage6RecoveryWorker) {
      g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] exiting worker after null-stack Stage6 GL callback tail "
          "in UpdateSurfaceAppWithPlatformParams\n";
      write(2, msg, sizeof(msg) - 1);
      pthread_mutex_unlock(&g_engine_gl_mutex);
      ExitCurrentThreadImmediately();
    }
    if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
        g_start_app_with_params_recovery_in_progress == kStage6RecoveryWorker) {
      g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] exiting worker after null-stack Stage6 GL callback tail "
          "in nativeAppBridgeV2StartAppWithParams\n";
      write(2, msg, sizeof(msg) - 1);
      pthread_mutex_unlock(&g_engine_gl_mutex);
      ExitCurrentThreadImmediately();
    }
    if (g_start_lua_app_dm_recovery_in_progress != 0) {
      g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] recovered nativeAppBridgeStartLuaAppDM after null-stack "
          "Stage6 GL callback tail\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
      return;
    }
    if (g_update_surface_app_recovery_in_progress != 0) {
      g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] recovered UpdateSurfaceAppWithPlatformParams after "
          "null-stack Stage6 GL callback tail\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_update_surface_app_jmp_buf, 1);
      return;
    }
    if (g_start_app_with_params_recovery_in_progress != 0) {
      g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
      const char msg[] =
          "  [patch] recovered nativeAppBridgeV2StartAppWithParams after "
          "null-stack Stage6 GL callback tail\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_start_app_with_params_jmp_buf, 1);
      return;
    }
  }
  if (g_current_stage >= 6 && instruction_readable &&
      libroblox_offset >= kStage6GlReturnedQueueScanStartOffset &&
      libroblox_offset <= kStage6GlReturnedQueueScanEndOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x02 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]) <
          kStage6LikelyHostPointerThreshold) {
    ++g_stage6_empty_gl_helper_returns;
    if (g_stage6_empty_gl_helper_returns >=
            kStage6GameGlobalInitEmptyReturnedQueueLimit &&
        g_game_global_init_recovery_in_progress != 0) {
      g_game_global_init_recovery_in_progress = 0;
      const char msg[] =
          "  [patch] recovered nativeGameGlobalInit after empty Stage6 GL "
          "returned-queue loop\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_game_global_init_jmp_buf, 1);
      return;
    }
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] returned empty Stage6 GL returned-queue scan "
          "rip=%p off=0x%lx old_rdx=%p return_off=0x%lx\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
          static_cast<unsigned long>(kStage6GlReturnedQueueEmptyReturnOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(base + kStage6GlReturnedQueueEmptyReturnOffset);
    return;
  }
  if (g_current_stage >= 6 && instruction_readable &&
      (libroblox_offset == kStage6GlReturnedQueueAtomicReadOffset ||
       libroblox_offset == kStage6GlReturnedQueueAtomicReadNextOffset) &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x02 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]) <
          kStage6LikelyHostPointerThreshold) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    uintptr_t queue = scratch + 0x1800;
    uintptr_t queue_atomic = scratch + 0x1a60;
    *reinterpret_cast<uint64_t*>(queue_atomic) = 0;
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[540];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] redirected Stage6 GL returned queue atomic "
          "rip=%p off=0x%lx old_rdx=%p state=%p queue=%p cell=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
          reinterpret_cast<void*>(state), reinterpret_cast<void*>(queue),
          reinterpret_cast<void*>(queue_atomic));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RDX] = static_cast<greg_t>(queue_atomic);
    return;
  }
  const uintptr_t fault_address =
      info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0;
  const uintptr_t fault_rax =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
  const bool is_invalid_stage6_gl_helper_pointer =
      fault_address < kStage5LowAddressThreshold ||
      (is_gl_counter_read && fault_address == fault_rax &&
       fault_rax < kStage6LikelyHostPointerThreshold);
  if (g_current_stage >= 6 &&
      (is_gl_state_read_rdx || is_gl_state_read_r15 || is_gl_state_read_rdi ||
       is_gl_queue_read_rax || is_gl_state_flag_read_eax ||
       is_gl_counter_read || is_gl_queue_self_compare) &&
      info && is_invalid_stage6_gl_helper_pointer) {
    uintptr_t scratch = reinterpret_cast<uintptr_t>(g_stage6_gl_scratch);
    InitialiseStage6GlScratch(g_stage6_gl_scratch);
    uintptr_t state = scratch + 0x1000;
    if (is_gl_queue_self_compare) {
      ++g_stage6_empty_gl_helper_returns;
      if (g_stage6_empty_gl_helper_returns > 8 &&
          g_call_messages_from_main_thread_recovery_in_progress != 0) {
        g_call_messages_from_main_thread_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] aborted nativeCallMessagesFromMainThread after empty "
            "Stage6 GL helper loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_call_messages_from_main_thread_jmp_buf, 1);
        return;
      }
      if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
          g_stage6_empty_gl_helper_returns > 8 &&
          g_start_lua_app_dm_recovery_in_progress == kStage6RecoveryWorker) {
        g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
        const char msg[] =
            "  [patch] exiting worker after empty Stage6 GL helper loop in "
            "nativeAppBridgeStartLuaAppDM\n";
        write(2, msg, sizeof(msg) - 1);
        ExitCurrentThreadImmediately();
      }
      if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
          g_stage6_empty_gl_helper_returns > 8 &&
          g_update_surface_app_recovery_in_progress == kStage6RecoveryWorker) {
        g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
        const char msg[] =
            "  [patch] exiting worker after empty Stage6 GL helper loop in "
            "UpdateSurfaceAppWithPlatformParams\n";
        write(2, msg, sizeof(msg) - 1);
        pthread_mutex_unlock(&g_engine_gl_mutex);
        ExitCurrentThreadImmediately();
      }
      if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
          g_stage6_empty_gl_helper_returns > 8 &&
          g_start_app_with_params_recovery_in_progress ==
              kStage6RecoveryWorker) {
        g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
        const char msg[] =
            "  [patch] exiting worker after empty Stage6 GL helper loop in "
            "nativeAppBridgeV2StartAppWithParams\n";
        write(2, msg, sizeof(msg) - 1);
        pthread_mutex_unlock(&g_engine_gl_mutex);
        ExitCurrentThreadImmediately();
      }
      if (g_stage6_empty_gl_helper_returns > 8 &&
          g_start_lua_app_dm_recovery_in_progress != 0) {
        g_start_lua_app_dm_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered nativeAppBridgeStartLuaAppDM after empty "
            "Stage6 GL helper loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
        return;
      }
      if (g_stage6_empty_gl_helper_returns > 8 &&
          g_update_surface_app_recovery_in_progress != 0) {
        g_update_surface_app_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered UpdateSurfaceAppWithPlatformParams after "
            "empty Stage6 GL helper loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_update_surface_app_jmp_buf, 1);
        return;
      }
      if (g_stage6_empty_gl_helper_returns > 8 &&
          g_start_app_with_params_recovery_in_progress != 0) {
        g_start_app_with_params_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered nativeAppBridgeV2StartAppWithParams after "
            "empty Stage6 GL helper loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_start_app_with_params_jmp_buf, 1);
        return;
      }
      if (g_stage6_gl_state_scratch_logs < 40) {
        char msg[460];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] returned from empty Stage6 GL helper "
            "rip=%p off=0x%lx si_addr=%p old_rsi=%p return=%p\n",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            static_cast<unsigned long>(libroblox_offset), info->si_addr,
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
            reinterpret_cast<void*>(static_cast<uintptr_t>(g_libroblox_base) +
                                    kStage6GlHelperReturnOffset));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_R15] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(static_cast<uintptr_t>(g_libroblox_base) +
                              kStage6GlHelperReturnOffset);
      return;
    }
    if (is_gl_queue_read_rax) {
      uintptr_t queue = scratch + 0x1800;
      uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      if (rbp >= 0x1000) {
        *reinterpret_cast<uint64_t*>(rbp - 0x88) =
            static_cast<uint64_t>(scratch);
      }
      if (g_stage6_gl_state_scratch_logs < 40) {
        char msg[520];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] redirected Stage6 GL queue read "
            "rip=%p off=0x%lx si_addr=%p old_rax=%p tls=%p state=%p queue=%p "
            "saved_tls_slot=%p\n",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            static_cast<unsigned long>(libroblox_offset), info->si_addr,
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
            reinterpret_cast<void*>(scratch), reinterpret_cast<void*>(state),
            reinterpret_cast<void*>(queue),
            reinterpret_cast<void*>(rbp >= 0x1000 ? rbp - 0x88 : 0));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++g_stage6_gl_state_scratch_logs;
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(queue);
      return;
    }
    if (g_stage6_gl_state_scratch_logs < 40) {
      char msg[460];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] redirected Stage6 GL state read "
          "rip=%p off=0x%lx si_addr=%p old_rax=%p scratch=%p state=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          static_cast<unsigned long>(libroblox_offset), info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          reinterpret_cast<void*>(scratch), reinterpret_cast<void*>(state));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_gl_state_scratch_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(scratch);
    return;
  }

  if (g_current_stage >= 6 && ucontext != nullptr &&
      IsEnabled("MOCKTAIL_SKIP_FAULTING_EMUTLS_INITIALIZER")) {
    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (IsReadableMemoryRange(reinterpret_cast<uintptr_t>(stack),
                              sizeof(uintptr_t))) {
      uintptr_t return_address = stack[0];
      uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
      uintptr_t return_offset =
          (base != 0 && return_address >= base) ? return_address - base : 0;
      if (return_offset == 0x2c18f12 || return_offset == 0x2c18f1e) {
        char msg[420];
        int len = snprintf(
            msg, sizeof(msg),
            "  [patch] skipped faulting emutls initializer memset/memcpy "
            "rip=%p si_addr=%p return=%p rbx=%p rdx=%p\n",
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
            info ? info->si_addr : nullptr,
            reinterpret_cast<void*>(return_address),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
            reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(return_address);
        ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
        return;
      }
    }
  }

  if (g_current_stage >= 6 && ucontext != nullptr) {
    constexpr uintptr_t kNullableVtableProbeOffset = 0x2bcd32a;
    constexpr uintptr_t kNullableVtableProbeReturnOffset = 0x2bcd360;
    constexpr uintptr_t kNullableVtableWrapperProbeOffset = 0x2bcd37d;
    constexpr uintptr_t kNullableVtableWrapperReturnOffset = 0x2bcd3d9;
    constexpr uintptr_t kStartupGuardTrapResumeOffset = 0x6a9ce1a;
    constexpr uintptr_t kStartupGuardTrapMiddleOffset = 0x6a9ce1b;
    constexpr uintptr_t kStartupGuardTrapReturnOffset = 0x6a9ce25;
    if (libroblox_offset == kStartupGuardTrapResumeOffset ||
        libroblox_offset == kStartupGuardTrapMiddleOffset) {
      ++g_stage6_empty_gl_helper_returns;
      if (TryRecoverRepeatedStage6GuardLoop()) {
        return;
      }
      if (g_stage6_empty_gl_helper_returns > 128 &&
          g_game_global_init_recovery_in_progress != 0) {
        g_game_global_init_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered nativeGameGlobalInit after repeated startup "
            "guard loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_game_global_init_jmp_buf, 1);
        return;
      }
      uintptr_t stack0 = 0;
      uintptr_t stack1 = 0;
      uintptr_t stack2 = 0;
      uintptr_t stack3 = 0;
      uintptr_t stack0_off = 0;
      uintptr_t stack1_off = 0;
      uintptr_t stack2_off = 0;
      uintptr_t stack3_off = 0;
      uintptr_t rbp_return = 0;
      uintptr_t rbp_return_off = 0;
      uintptr_t scan_offsets[8] = {};
      size_t scan_count = 0;
      const uintptr_t rsp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
      const uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      const uintptr_t base =
          static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
      auto offset_if_text = [base](uintptr_t value) -> uintptr_t {
        if (base != 0 && value >= base &&
            value < base + kLibrobloxExecutableSegmentEndOffset) {
          return value - base;
        }
        return 0;
      };
      if (IsReadableMemoryRange(rsp, 4 * sizeof(uintptr_t))) {
        const auto* stack = reinterpret_cast<const uintptr_t*>(rsp);
        stack0 = stack[0];
        stack1 = stack[1];
        stack2 = stack[2];
        stack3 = stack[3];
        stack0_off = offset_if_text(stack0);
        stack1_off = offset_if_text(stack1);
        stack2_off = offset_if_text(stack2);
        stack3_off = offset_if_text(stack3);
      }
      if (IsReadableMemoryRange(rbp + sizeof(uintptr_t), sizeof(uintptr_t))) {
        rbp_return = ReadPointerIfReadable(rbp + sizeof(uintptr_t));
        rbp_return_off = offset_if_text(rbp_return);
      }
      if (IsReadableMemoryRange(rsp, 64 * sizeof(uintptr_t))) {
        const auto* stack = reinterpret_cast<const uintptr_t*>(rsp);
        for (size_t i = 0; i < 64 && scan_count < 8; ++i) {
          const uintptr_t offset = offset_if_text(stack[i]);
          if (offset != 0) {
            scan_offsets[scan_count++] = offset;
          }
        }
      }
      char msg[1040];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [patch] skipped startup guard trap tail "
                   "rip_off=0x%lx return_off=0x%lx "
                   "stack0=%p/off=0x%lx stack1=%p/off=0x%lx "
                   "stack2=%p/off=0x%lx stack3=%p/off=0x%lx\n",
                   static_cast<unsigned long>(libroblox_offset),
                   static_cast<unsigned long>(kStartupGuardTrapReturnOffset),
                   reinterpret_cast<void*>(stack0),
                   static_cast<unsigned long>(stack0_off),
                   reinterpret_cast<void*>(stack1),
                   static_cast<unsigned long>(stack1_off),
                   reinterpret_cast<void*>(stack2),
                   static_cast<unsigned long>(stack2_off),
                   reinterpret_cast<void*>(stack3),
                   static_cast<unsigned long>(stack3_off));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 startup guard trap stack scan "
          "rbp=%p rbp_ret=%p/off=0x%lx hits=%zu "
          "offsets{0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx}\n",
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(rbp_return),
          static_cast<unsigned long>(rbp_return_off), scan_count,
          static_cast<unsigned long>(scan_offsets[0]),
          static_cast<unsigned long>(scan_offsets[1]),
          static_cast<unsigned long>(scan_offsets[2]),
          static_cast<unsigned long>(scan_offsets[3]),
          static_cast<unsigned long>(scan_offsets[4]),
          static_cast<unsigned long>(scan_offsets[5]),
          static_cast<unsigned long>(scan_offsets[6]),
          static_cast<unsigned long>(scan_offsets[7]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(static_cast<uintptr_t>(g_libroblox_base) +
                              kStartupGuardTrapReturnOffset);
      return;
    }
    if (libroblox_offset == kNullableVtableProbeOffset &&
        ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
      ++g_stage6_empty_gl_helper_returns;
      if (TryRecoverRepeatedStage6GuardLoop()) {
        return;
      }
      if (g_stage6_empty_gl_helper_returns > 128 &&
          g_game_global_init_recovery_in_progress != 0) {
        g_game_global_init_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered nativeGameGlobalInit after repeated null "
            "vtable probe loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_game_global_init_jmp_buf, 1);
        return;
      }
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped null vtable probe "
          "rip_off=0x%lx rsi=%p return_off=0x%lx\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          static_cast<unsigned long>(kNullableVtableProbeReturnOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(static_cast<uintptr_t>(g_libroblox_base) +
                              kNullableVtableProbeReturnOffset);
      return;
    }
    if (libroblox_offset == kNullableVtableWrapperProbeOffset &&
        ucontext->uc_mcontext.gregs[REG_RCX] == 0) {
      ++g_stage6_empty_gl_helper_returns;
      if (TryRecoverRepeatedStage6GuardLoop()) {
        return;
      }
      if (g_stage6_empty_gl_helper_returns > 128 &&
          g_game_global_init_recovery_in_progress != 0) {
        g_game_global_init_recovery_in_progress = 0;
        const char msg[] =
            "  [patch] recovered nativeGameGlobalInit after repeated null "
            "wrapper vtable probe loop\n";
        write(2, msg, sizeof(msg) - 1);
        siglongjmp(g_game_global_init_jmp_buf, 1);
        return;
      }
      char msg[340];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped null wrapper vtable probe "
          "rip_off=0x%lx rax=%p return_off=0x%lx\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
          static_cast<unsigned long>(kNullableVtableWrapperReturnOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(static_cast<uintptr_t>(g_libroblox_base) +
                              kNullableVtableWrapperReturnOffset);
      return;
    }

    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (stack != nullptr) {
      uintptr_t return_address = stack[0];
      uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
      uintptr_t return_offset =
          (base != 0 && return_address >= base) ? return_address - base : 0;
      uintptr_t key_address =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
      uintptr_t key_offset =
          (base != 0 && key_address >= base) ? key_address - base : 0;
      bool key_is_static_libroblox_data =
          base != 0 && key_address >= base &&
          key_address + sizeof(uint64_t) * 4 >= key_address &&
          key_address + sizeof(uint64_t) * 4 <= base + 0x9000000;
      if (return_offset == 0x2c18f1e && key_is_static_libroblox_data) {
        const auto* key = reinterpret_cast<const uint64_t*>(key_address);
        uint64_t size = key[0];
        uint64_t align = key[1];
        uint64_t initializer = key[3];
        uintptr_t value =
            static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
        if (value == 0) {
          value = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
        }
        bool valid_zero_initializer = initializer == 0 && size > 0 &&
                                      size <= 0x10000 && align > 0 &&
                                      (align & (align - 1)) == 0;
        if (valid_zero_initializer) {
          auto* bytes = reinterpret_cast<volatile unsigned char*>(value);
          for (uint64_t i = 0; i < size; ++i) {
            bytes[i] = 0;
          }
          char msg[460];
          int len = snprintf(
              msg, sizeof(msg),
              "  [patch] completed emutls zero initializer manually "
              "key_off=0x%lx size=0x%llx align=0x%llx value=%p return=%p\n",
              static_cast<unsigned long>(key_offset),
              static_cast<unsigned long long>(size),
              static_cast<unsigned long long>(align),
              reinterpret_cast<void*>(value),
              reinterpret_cast<void*>(return_address));
          if (len > 0) {
            write(2, msg, static_cast<size_t>(len));
          }
          ucontext->uc_mcontext.gregs[REG_RIP] =
              static_cast<greg_t>(return_address);
          ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
          return;
        }
      }
    }
  }

  if (g_current_stage >= 6 && g_set_asset_path_recovery_in_progress != 0) {
    g_set_asset_path_recovery_in_progress = 0;
    {
      char dbg[256];
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativeSetAssetPath: RIP=%p si_addr=%p signo=%d\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          info ? info->si_addr : nullptr, signo);
      if (n > 0) write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] =
        "  [patch] recovered from SIG in nativeSetAssetPath (early)\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_set_asset_path_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_game_global_init_recovery_in_progress != 0) {
    g_game_global_init_recovery_in_progress = 0;
    {
      char dbg[720];
      uintptr_t stack0 = 0;
      uintptr_t stack1 = 0;
      uintptr_t stack2 = 0;
      uintptr_t stack3 = 0;
      uintptr_t stack0_off = 0;
      uintptr_t stack1_off = 0;
      if (ucontext != nullptr) {
        auto* stack =
            reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
        stack0 = stack[0];
        stack1 = stack[1];
        stack2 = stack[2];
        stack3 = stack[3];
        uintptr_t base =
            static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
        if (base != 0 && stack0 >= base) {
          stack0_off = stack0 - base;
        }
        if (base != 0 && stack1 >= base) {
          stack1_off = stack1 - base;
        }
      }
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativeGameGlobalInit: RIP=%p si_addr=%p "
          "signo=%d rdi=%p rsi=%p rdx=%p rax=%p rcx=%p "
          "stack0=%p/off=0x%lx stack1=%p/off=0x%lx stack2=%p stack3=%p\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          info ? info->si_addr : nullptr, signo,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
              : nullptr,
          reinterpret_cast<void*>(stack0),
          static_cast<unsigned long>(stack0_off),
          reinterpret_cast<void*>(stack1),
          static_cast<unsigned long>(stack1_off),
          reinterpret_cast<void*>(stack2), reinterpret_cast<void*>(stack3));
      if (n > 0) write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] = "  [patch] recovered from SIG in nativeGameGlobalInit\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_game_global_init_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_init_client_settings_recovery_in_progress != 0) {
    g_init_client_settings_recovery_in_progress = 0;
    {
      char dbg[420];
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativeInitClientSettings: RIP=%p si_addr=%p "
          "signo=%d rax=%p rbx=%p rcx=%p rdx=%p r13=%p\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          info ? info->si_addr : nullptr, signo,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13])
              : nullptr);
      if (n > 0) write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] =
        "  [patch] recovered from SIG in nativeInitClientSettings\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_init_client_settings_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_post_client_settings_recovery_in_progress != 0) {
    g_post_client_settings_recovery_in_progress = 0;
    {
      char dbg[420];
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativePostClientSettingsLoadedInitialization3: "
          "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rbx=%p rcx=%p "
          "rdx=%p rsi=%p rdi=%p\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          static_cast<unsigned long>(libroblox_offset),
          info ? info->si_addr : nullptr, signo,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
              : nullptr);
      if (n > 0) {
        write(2, dbg, static_cast<size_t>(n));
      }
    }
    const char msg[] =
        "  [patch] recovered from SIG in "
        "nativePostClientSettingsLoadedInitialization3\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_post_client_settings_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_initialize_native_flags_recovery_in_progress != 0) {
    g_initialize_native_flags_recovery_in_progress = 0;
    {
      char dbg[420];
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativeInitializeNativeFlags: "
          "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rbx=%p rcx=%p "
          "rdx=%p rsi=%p rdi=%p\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          static_cast<unsigned long>(libroblox_offset),
          info ? info->si_addr : nullptr, signo,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
              : nullptr);
      if (n > 0) {
        write(2, dbg, static_cast<size_t>(n));
      }
    }
    const char msg[] =
        "  [patch] recovered from SIG in nativeInitializeNativeFlags\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_initialize_native_flags_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_app_bridge_app_start_recovery_in_progress != 0) {
    g_app_bridge_app_start_recovery_in_progress = 0;
    {
      char dbg[420];
      int n = snprintf(
          dbg, sizeof(dbg),
          "  [patch] SIG in nativeAppBridgeAppStart: "
          "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rbx=%p rcx=%p "
          "rdx=%p rsi=%p rdi=%p\n",
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
              : nullptr,
          static_cast<unsigned long>(libroblox_offset),
          info ? info->si_addr : nullptr, signo,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
              : nullptr);
      if (n > 0) {
        write(2, dbg, static_cast<size_t>(n));
      }
    }
    const char msg[] =
        "  [patch] recovered from SIG in nativeAppBridgeAppStart\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_app_bridge_app_start_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && is_zero_page_instruction) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected zero-byte Stage6 execute fault to caller "
          "return\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    uintptr_t return_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (return_slot != 0) {
      auto* return_addr = reinterpret_cast<uintptr_t*>(return_slot);
      if (return_addr != nullptr && *return_addr != 0) {
        ucontext->uc_mcontext.gregs[REG_RIP] =
            static_cast<greg_t>(*return_addr);
        ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t);
        return;
      }
    }
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(reinterpret_cast<uintptr_t>(instruction) + 1);
    return;
  }

  if (g_current_stage >= 6 && g_cookie_setter_recovery_in_progress != 0) {
    g_cookie_setter_recovery_in_progress = 0;
    const char msg[] = "  [patch] recovered from SIG in native cookie setter\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_cookie_setter_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_native_settings_recovery_in_progress != 0) {
    g_native_settings_recovery_in_progress = 0;
    char dbg[420];
    int n = snprintf(
        dbg, sizeof(dbg),
        "  [patch] SIG in NativeSettings setter %s: "
        "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rbx=%p rsi=%p rdi=%p\n",
        g_native_settings_recovery_name != nullptr
            ? g_native_settings_recovery_name
            : "(unknown)",
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
                 : nullptr,
        static_cast<unsigned long>(libroblox_offset),
        info ? info->si_addr : nullptr, signo,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
                 : nullptr);
    if (n > 0) {
      write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] =
        "  [patch] recovered from SIG in NativeSettings setter\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_native_settings_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_init_with_params_recovery_in_progress != 0) {
    g_init_with_params_recovery_in_progress = 0;
    uintptr_t rsp = 0;
    uintptr_t rbp = 0;
    uintptr_t stack0 = 0;
    uintptr_t frame_ret = 0;
    if (ucontext != nullptr) {
      rsp = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
      rbp = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
        stack0 = *reinterpret_cast<const uintptr_t*>(rsp);
      }
      if (IsReadableMemoryRange(rbp, sizeof(uintptr_t) * 2)) {
        const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
        frame_ret = frame[1];
      }
    }
    const uintptr_t stack0_offset =
        (g_libroblox_base != 0 && stack0 >= g_libroblox_base)
            ? stack0 - g_libroblox_base
            : 0;
    const uintptr_t frame_ret_offset =
        (g_libroblox_base != 0 && frame_ret >= g_libroblox_base)
            ? frame_ret - g_libroblox_base
            : 0;
    char dbg[980];
    int n = snprintf(
        dbg, sizeof(dbg),
        "  [patch] SIG in nativeAppBridgeV2InitWithParams: "
        "RIP=%p off=0x%lx si_addr=%p signo=%d "
        "rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p "
        "r8=%p r9=%p r12=%p r13=%p r14=%p r15=%p "
        "rsp=%p rbp=%p stack0=%p stack0_off=0x%lx "
        "frame_ret=%p frame_ret_off=0x%lx\n",
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
                 : nullptr,
        static_cast<unsigned long>(libroblox_offset),
        info ? info->si_addr : nullptr, signo,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15])
                 : nullptr,
        reinterpret_cast<void*>(rsp), reinterpret_cast<void*>(rbp),
        reinterpret_cast<void*>(stack0),
        static_cast<unsigned long>(stack0_offset),
        reinterpret_cast<void*>(frame_ret),
        static_cast<unsigned long>(frame_ret_offset));
    if (n > 0) {
      write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] =
        "  [patch] recovered from SIG in nativeAppBridgeV2InitWithParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_init_with_params_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_game_activity_init_recovery_in_progress != 0) {
    g_game_activity_init_recovery_in_progress = 0;
    char dbg[360];
    int n = snprintf(
        dbg, sizeof(dbg),
        "  [patch] SIG in GameActivity.initializeNativeCode: "
        "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rdi=%p rsi=%p\n",
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
                 : nullptr,
        static_cast<unsigned long>(libroblox_offset),
        info ? info->si_addr : nullptr, signo,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
                 : nullptr);
    if (n > 0) {
      write(2, dbg, static_cast<size_t>(n));
    }
    const char msg[] =
        "  [patch] recovered from SIG in GameActivity.initializeNativeCode\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_game_activity_init_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_game_activity_surface_recovery_in_progress != 0) {
    g_game_activity_surface_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from SIG in GameActivity surface callbacks\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_game_activity_surface_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_activity_lifecycle_recovery_in_progress != 0) {
    if (TryReturnFromStage6ActivityLifecycleNullObserver(ucontext,
                                                         libroblox_offset)) {
      return;
    }
    g_activity_lifecycle_recovery_in_progress = 0;
    LogStage6RecoverySignal("activity lifecycle callbacks", ucontext, info,
                            signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in activity lifecycle callbacks\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_activity_lifecycle_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_update_screen_orientation_recovery_in_progress != 0) {
    g_update_screen_orientation_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeUpdateScreenOrientation", ucontext, info,
                            signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in nativeUpdateScreenOrientation\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_screen_orientation_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && ucontext != nullptr && instruction_readable &&
      libroblox_base != 0 &&
      libroblox_offset == kStage6LibcxxGuardReleaseNullStoreOffset &&
      instruction[0] == 0xc6 && instruction[1] == 0x07 &&
      instruction[2] == 0x01 && ucontext->uc_mcontext.gregs[REG_RDI] == 0 &&
      (g_start_app_with_params_recovery_in_progress != 0 ||
       g_update_surface_app_recovery_in_progress != 0 ||
       g_start_lua_app_dm_recovery_in_progress != 0)) {
    char msg[320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 null libcxx guard release skipped "
        "rip_off=0x%lx return_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        static_cast<unsigned long>(kStage6LibcxxGuardReleaseReturnOffset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6LibcxxGuardReleaseReturnOffset);
    return;
  }

  if (g_current_stage >= 6 && g_update_surface_app_recovery_in_progress != 0) {
    if (TryReturnFromStage6UpdateSurfaceNonCodeCallback(signo, info,
                                                        ucontext)) {
      return;
    }
    g_update_surface_app_recovery_in_progress = 0;
    LogStage6RecoverySignal("UpdateSurfaceAppWithPlatformParams", ucontext,
                            info, signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in UpdateSurfaceAppWithPlatformParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_surface_app_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_call_messages_from_main_thread_recovery_in_progress != 0) {
    g_call_messages_from_main_thread_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeCallMessagesFromMainThread", ucontext, info,
                            signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in nativeCallMessagesFromMainThread\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_call_messages_from_main_thread_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_native_fragment_start_recovery_in_progress != 0) {
    g_native_fragment_start_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeOnFragmentStart", ucontext, info, signo,
                            libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in nativeOnFragmentStart\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_native_fragment_start_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 &&
      g_display_refresh_rate_recovery_in_progress != 0) {
    g_display_refresh_rate_recovery_in_progress = 0;
    LogStage6RecoverySignal("display refresh-rate JNI", ucontext, info, signo,
                            libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in display refresh-rate JNI\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_display_refresh_rate_jmp_buf, 1);
    return;
  }

  if (TryReturnFromStage6ErroneousFunctionPointerCall(signo, info, ucontext)) {
    return;
  }

  if (g_current_stage >= 6 &&
      g_start_app_with_params_recovery_in_progress != 0) {
    if (IsEnabled("MOCKTAIL_NO_RECOVER_START_APP")) {
      return;
    }
    if (TryReturnFromStage6ActivityLifecycleNullObserver(ucontext,
                                                         libroblox_offset)) {
      const char msg[] =
          "  [patch] recovered empty activity-lifecycle observer inside "
          "StartAppWithParams\n";
      write(2, msg, sizeof(msg) - 1);
      return;
    }
    g_start_app_with_params_recovery_in_progress = 0;
    LogStage6StartAppNonCodeTargetDetail(ucontext);
    LogStage6RecoverySignal("nativeAppBridgeV2StartAppWithParams", ucontext,
                            info, signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in nativeAppBridgeV2StartAppWithParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_app_with_params_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_start_lua_app_dm_recovery_in_progress != 0) {
    if (TryRecoverStage6StartLuaTargetTableDynamicCastTypeInfo(
            ucontext, libroblox_offset)) {
      return;
    }
    const uintptr_t rsp =
        ucontext ? static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP])
                 : 0;
    const uintptr_t stack0 = ReadPointerIfReadable(rsp);
    const uintptr_t stack1 = ReadPointerIfReadable(rsp + sizeof(uintptr_t));
    const uintptr_t offset_base =
        g_libroblox_base != 0 ? g_libroblox_base : libroblox_base;
    const uintptr_t stack0_offset =
        (offset_base != 0 && stack0 >= offset_base) ? stack0 - offset_base : 0;
    const uintptr_t stack1_offset =
        (offset_base != 0 && stack1 >= offset_base) ? stack1 - offset_base : 0;
    char dbg[620];
    int n = snprintf(
        dbg, sizeof(dbg),
        "  [patch] SIG in nativeAppBridgeStartLuaAppDM: "
        "RIP=%p off=0x%lx si_addr=%p signo=%d rax=%p rbx=%p rsi=%p rdi=%p "
        "rsp=%p stack0=%p/off=0x%lx stack1=%p/off=0x%lx\n",
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
                 : nullptr,
        static_cast<unsigned long>(libroblox_offset),
        info ? info->si_addr : nullptr, signo,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
                 : nullptr,
        ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
                 : nullptr,
        reinterpret_cast<void*>(rsp), reinterpret_cast<void*>(stack0),
        static_cast<unsigned long>(stack0_offset),
        reinterpret_cast<void*>(stack1),
        static_cast<unsigned long>(stack1_offset));
    if (n > 0) {
      write(2, dbg, static_cast<size_t>(n));
    }
    const uintptr_t instruction_address =
        ucontext ? static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP])
                 : 0;
    const bool rip_is_libroblox_text =
        offset_base != 0 &&
        instruction_address >= offset_base + kLibrobloxTextStartOffset &&
        instruction_address <
            offset_base + kLibrobloxExecutableSegmentEndOffset;
    if (!rip_is_libroblox_text && stack0_offset >= kLibrobloxTextStartOffset &&
        stack0_offset < kLibrobloxExecutableSegmentEndOffset) {
      char skip_msg[620];
      int skip_len = snprintf(
          skip_msg, sizeof(skip_msg),
          "  [patch] skipped Stage6 StartLua non-code callback target "
          "target=%p return_off=0x%lx rax=%p rdi=%p "
          "source=startLua-recovery\n",
          reinterpret_cast<void*>(instruction_address),
          static_cast<unsigned long>(stack0_offset),
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
              : nullptr,
          ucontext
              ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
              : nullptr);
      if (skip_len > 0) {
        write(2, skip_msg, static_cast<size_t>(skip_len));
      }
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(stack0);
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp + sizeof(uintptr_t));
      return;
    }
    g_start_lua_app_dm_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from SIG in nativeAppBridgeStartLuaAppDM\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
    return;
  }

  if (signo == SIGTRAP && g_current_stage >= 6 &&
      g_start_game_with_param_recovery_in_progress != 0 &&
      libroblox_base != 0 && ucontext != nullptr &&
      (libroblox_offset == kStage6StartGameAssetLookupAtIndexAssertOffset ||
       libroblox_offset == kStage6StartGameAssetLookupAtIndexAssertOffset + 1 ||
       libroblox_offset == kStage6StartGameAssetLoopAtIndexAssertOffset ||
       libroblox_offset == kStage6StartGameAssetLoopAtIndexAssertOffset + 1)) {
    const bool loop =
        libroblox_offset == kStage6StartGameAssetLoopAtIndexAssertOffset ||
        libroblox_offset == kStage6StartGameAssetLoopAtIndexAssertOffset + 1;
    const uintptr_t return_offset =
        loop ? kStage6StartGameAssetLoopAtIndexReturnOffset
             : kStage6StartGameAssetLookupAtIndexReturnOffset;
    const uintptr_t container =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uint32_t index =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uint32_t count =
        IsReadableMemoryRange(container + 0x04, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(container + 0x04)
            : 0xffffffffu;
    const uintptr_t item_base = ReadPointerIfReadable(container + 0x10);
    const uintptr_t bitset = ReadPointerIfReadable(container + 0x08);
    const uint64_t bit0 = ReadPointerIfReadable(bitset + 0x18);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartGame asset at_index invalid: "
        "clamping to zero rip_off=0x%lx which=%s container=%p "
        "index=0x%x count=0x%x item_base=%p bitset=%p bit0=0x%llx "
        "return_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset), loop ? "loop" : "lookup",
        reinterpret_cast<void*>(container), index, count,
        reinterpret_cast<void*>(item_base), reinterpret_cast<void*>(bitset),
        static_cast<unsigned long long>(bit0),
        static_cast<unsigned long>(return_offset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + return_offset);
    return;
  }

  if (g_current_stage >= 6 &&
      g_start_game_with_param_recovery_in_progress != 0 && info &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6StartGameAssetLookupNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x78 && instruction[3] == 0x18 && ucontext != nullptr &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    const uintptr_t base =
        reinterpret_cast<uintptr_t>(g_stage6_start_game_base_scratch);
    const uintptr_t r14 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    if (r14 == base) {
      const uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      const uint32_t lookup_index =
          IsReadableMemoryRange(rbp - 0x168, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(rbp - 0x168)
              : 0xffffffffu;
      const uintptr_t item =
          PrepareStage6StartGameEmptyItemScratch("asset lookup null holder");
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartGame asset lookup holder missing: "
          "returning empty item rip_off=0x%lx base=%p holder=%p "
          "index=0x%x item=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(base),
          reinterpret_cast<void*>(ReadPointerIfReadable(base + 0x4648)),
          lookup_index, reinterpret_cast<void*>(item));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(item);
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartGameAssetLookupNullReturnOffset);
      return;
    }
  }

  if (g_current_stage >= 6 &&
      g_start_game_with_param_recovery_in_progress != 0 && info &&
      instruction_readable && libroblox_base != 0 &&
      libroblox_offset == kStage6StartGameAssetLoopNullReadOffset &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x78 && instruction[3] == 0x18 && ucontext != nullptr &&
      ucontext->uc_mcontext.gregs[REG_RAX] == 0) {
    char msg[440];
    const uint32_t loop_index =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartGame asset loop holder missing: "
        "using sentinel result rip_off=0x%lx index=0x%x r12=%p r13=%p\n",
        static_cast<unsigned long>(libroblox_offset), loop_index,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(0xffffffffu);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartGameAssetLoopNullReturnOffset);
    return;
  }

  if (g_current_stage >= 6 &&
      g_start_game_with_param_recovery_in_progress != 0) {
    g_start_game_with_param_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeAppBridgeV2StartGameWithParam", ucontext,
                            info, signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in nativeAppBridgeV2StartGameWithParam\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_game_with_param_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_send_app_ready_recovery_in_progress != 0) {
    g_send_app_ready_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeAppBridgeV2SendAppEventOnAppReady", ucontext,
                            info, signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in "
        "nativeAppBridgeV2SendAppEventOnAppReady\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_send_app_ready_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && g_send_game_loaded_recovery_in_progress != 0) {
    g_send_game_loaded_recovery_in_progress = 0;
    LogStage6RecoverySignal("nativeAppBridgeV2SendAppEventOnGameLoaded",
                            ucontext, info, signo, libroblox_offset);
    const char msg[] =
        "  [patch] recovered from SIG in "
        "nativeAppBridgeV2SendAppEventOnGameLoaded\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_send_game_loaded_jmp_buf, 1);
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kMaxCanonicalUserPointer &&
      instruction[0] == 0x49 && instruction[1] == 0x8b &&
      instruction[2] == 0x45) {
    if (g_stage6_invalid_r13_read_logs < 8) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] redirected Stage6 R13-based invalid load "
          "rip=%p si_addr=%p r13=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_invalid_r13_read_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kMaxCanonicalUserPointer &&
      instruction[0] == 0x4d && instruction[1] == 0x8b &&
      instruction[2] == 0x45) {
    if (g_stage6_invalid_r13_read_logs < 8) {
      char msg[320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] redirected Stage6 R13-based invalid load "
          "rip=%p si_addr=%p r13=%p\n",
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
          info->si_addr,
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13]));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++g_stage6_invalid_r13_read_logs;
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0x80 &&
      instruction[1] == 0x38 && instruction[2] == 0x00 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 cmp byte ptr [rax],0x00 fault\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    g_stage5_fallback_region[0] = 0;
    g_stage5_fallback_region[8] = 0;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region + 8);
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0x80 &&
      instruction[1] == 0x3b && instruction[2] == 0x00) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 cmp byte ptr [rbx],0x00 fault\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0x80 &&
      instruction[1] == 0x39 && instruction[2] == 0x00) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 cmp byte ptr [rcx],0x00 fault\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0xff && instruction[1] == 0x50 &&
      instruction[2] == 0x30) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 [rax+0x30] call through invalid base\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0xff &&
      instruction[1] == 0x50 && instruction[2] == 0x20) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 [rax+0x20] call through invalid base\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0xff && instruction[1] == 0x50 &&
      instruction[2] == 0x10) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 [rax+0x10] call through invalid base\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0xff && instruction[1] == 0x60 &&
      instruction[2] == 0x20) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 [rax+0x20] indirect call/jmp through "
          "invalid "
          "base\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x49 && instruction[1] == 0x8b &&
      instruction[2] == 0x5e && instruction[3] == 0x08) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 mov rbx,[r14+0x8] low-address deref\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) == 8 &&
      instruction[0] == 0x4d && instruction[1] == 0x8b &&
      instruction[2] == 0x6d && instruction[3] == 0x08) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 mov QWORD PTR [r13+0x8],r13 null deref\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) == 0 &&
      instruction[0] == 0x49 && instruction[1] == 0x8b &&
      instruction[2] == 0x07 && instruction[3] == 0x4c &&
      instruction[4] == 0x8d && instruction[5] == 0x6d &&
      instruction[6] == 0xc0 && instruction[7] == 0x4c &&
      instruction[8] == 0x89 && instruction[9] == 0xef &&
      instruction[10] == 0x4c && instruction[11] == 0x89 &&
      instruction[12] == 0xfe && instruction[13] == 0xff &&
      instruction[14] == 0x50 && instruction[15] == 0x20) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 nativePostClientSettings sequence "
          "r15-based call path\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 16;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) == 0 &&
      instruction[0] == 0x49 && instruction[1] == 0x8b &&
      instruction[2] == 0x07) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 mov QWORD PTR [r15],rax null deref\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R15] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }

  // libGLdispatch may access Bionic TLS keys through glibc thread state.
  if (g_current_stage >= 6 && module_name &&
      std::strstr(module_name, "libGLdispatch") != nullptr) {
    if (instruction[0] == 0x48 &&
        (instruction[1] == 0x89 || instruction[1] == 0x8b)) {
      int rm = instruction[2] & 7;
      int reg_map[] = {REG_RAX, REG_RCX, REG_RDX, REG_RBX,
                       -1,      -1,      REG_RSI, REG_RDI};
      if (rm < 8 && reg_map[rm] != -1) {
        uintptr_t old_val = ucontext->uc_mcontext.gregs[reg_map[rm]];
        if (old_val < kStage5LowAddressThreshold) {
          // Signal handlers cannot call malloc; each thread gets fixed scratch
          // storage to avoid sharing writes across recovered threads.
          pid_t tid = static_cast<pid_t>(syscall(SYS_gettid));
          void* thread_scratch = GetThreadScratchBuffer(tid);
          ucontext->uc_mcontext.gregs[reg_map[rm]] =
              reinterpret_cast<greg_t>(thread_scratch);
        } else if (old_val == reinterpret_cast<uintptr_t>(&NullVtableStub) ||
                   old_val == reinterpret_cast<uintptr_t>(kFallbackVtable)) {
          pid_t tid = static_cast<pid_t>(syscall(SYS_gettid));
          void* thread_scratch = GetThreadScratchBuffer(tid);
          ucontext->uc_mcontext.gregs[reg_map[rm]] =
              reinterpret_cast<greg_t>(thread_scratch);
        }

        if (g_skipped_headless_null_writes < 10) {
          char log_msg[256];
          int log_len =
              snprintf(log_msg, sizeof(log_msg),
                       "  [patch] GLdispatch recovery: redirected rm=%d (was "
                       "%p) to thread-specific scratch buffer\n",
                       rm, reinterpret_cast<void*>(old_val));
          if (log_len > 0) {
            write(2, log_msg, static_cast<size_t>(log_len));
          }
        }
        ++g_skipped_headless_null_writes;
        return;
      }
    }
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0xc7 &&
      ((instruction[2] & 0xc0) == 0x40) &&
      (((instruction[2] >> 3) & 0x7) == 0) && ((instruction[2] & 0x7) != 4)) {
    greg_t* base_reg = nullptr;
    switch (instruction[2] & 0x7) {
      case 0:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RAX];
        break;
      case 1:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RCX];
        break;
      case 2:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RDX];
        break;
      case 3:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RBX];
        break;
      case 5:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RBP];
        break;
      case 6:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RSI];
        break;
      case 7:
        base_reg = &ucontext->uc_mcontext.gregs[REG_RDI];
        break;
    }
    if (base_reg == nullptr ||
        static_cast<uintptr_t>(*base_reg) >= kStage5LowAddressThreshold) {
      goto skip_stage6_null_object_immediate_store;
    }
    if (g_skipped_headless_null_writes < 3) {
      const char msg[] =
          "  [patch] redirected Stage6 null object immediate store to "
          "fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    *base_reg = reinterpret_cast<greg_t>(g_stage5_fallback_region);
    if (static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) <
        kStage5LowAddressThreshold) {
      ucontext->uc_mcontext.gregs[REG_RBX] =
          reinterpret_cast<greg_t>(g_stage5_fallback_region);
    }
    return;
  }
skip_stage6_null_object_immediate_store:

  // Catch the remaining `48 89 ??` stores to low addresses.
  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x89) {
    if (g_skipped_headless_null_writes < 3) {
      const char msg[] =
          "  [patch] skipped Stage6 64-bit store to low/null address\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    uint8_t modrm = instruction[2];
    uint8_t mod = (modrm >> 6) & 0x3;
    // The ModR/M displacement determines how many instruction bytes to skip.
    int instr_len = (mod == 1) ? 4 : (mod == 2) ? 7 : 3;
    ucontext->uc_mcontext.gregs[REG_RIP] += instr_len;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0xff && instruction[1] == 0x90) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 [rax+disp] call through invalid base\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 6;
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) == 0 &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x06) {
    // Redirect the null receiver so a following vtable call reaches the stub.
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 mov rax,[rsi] (RSI=null) to fallback "
          "object\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RSI] =
        reinterpret_cast<greg_t>(kFallbackObject);
    // Re-run the load against the repaired receiver.
    return;
  }

  // The same recovery applies to nonzero addresses below the valid threshold.
  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x06) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 mov rax,[rsi] (low-addr) to fallback "
          "object\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RSI] =
        reinterpret_cast<greg_t>(kFallbackObject);
    return;
  }

  // libGLdispatch / Mesa: `mov rax,[rdi+0x10]` (48 8b 47 10) or
  // `mov rax,[rdi]` (48 8b 07) with RDI pointing to a tiny Bionic TLS key
  // address.  Redirect RDI to kFallbackObject so the read succeeds.
  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      (instruction[2] == 0x47 || instruction[2] == 0x07 ||
       instruction[2] == 0x40 || instruction[2] == 0x00)) {
    if (g_skipped_headless_null_writes < 3) {
      const char msg[] =
          "  [patch] redirected GLdispatch low-addr [rdi+N] read to fallback "
          "object\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(kFallbackObject);
    // Re-execute the load against the patched RDI.
    return;
  }

  // Redirect low `mov rax,[rax+N]` bases to the fallback vtable.
  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      (instruction[2] == 0x00 || instruction[2] == 0x40)) {
    if (g_skipped_headless_null_writes < 3) {
      const char msg[] =
          "  [patch] redirected low-addr [rax+N] read to fallback vtable\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(kFallbackVtable);
    return;
  }

  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold &&
      instruction[0] == 0x48 && instruction[1] == 0x8b &&
      instruction[2] == 0x18) {
    if (g_skipped_headless_null_writes < 8) {
      const char msg[] =
          "  [patch] redirected low-addr mov rbx,[rax] to zero scratch\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    *reinterpret_cast<uintptr_t*>(g_stage5_fallback_region) = 0;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (signo == SIGTRAP && g_current_stage >= 6 && libroblox_base != 0 &&
      (libroblox_offset == kStage6StartLuaGateStateLoadOffset ||
       libroblox_offset == kStage6StartLuaGateStateLoadOffset + 1)) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t state = 0;
    uint32_t phase = 0xffffffffu;
    uint64_t payload_first = 0;
    const bool state_slot_readable =
        IsReadableMemoryRange(owner + 0x418, sizeof(uintptr_t));
    if (state_slot_readable) {
      state = *reinterpret_cast<const uintptr_t*>(owner + 0x418);
    }
    if (IsReadableMemoryRange(state + 0x138, sizeof(uint32_t))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    if (IsReadableMemoryRange(payload, sizeof(uint64_t))) {
      payload_first = *reinterpret_cast<const uint64_t*>(payload);
    }

    char msg[620];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua gate state-load off=0x%lx "
        "owner=%p slot_readable=%d state=%p phase=0x%x "
        "payload=%p payload0=0x%llx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(owner), state_slot_readable ? 1 : 0,
        reinterpret_cast<void*>(state), phase, reinterpret_cast<void*>(payload),
        static_cast<unsigned long long>(payload_first));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(state);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaGateStateLoadOffset + 7);
    return;
  }

  if (signo == SIGTRAP && g_current_stage >= 6 && libroblox_base != 0 &&
      (libroblox_offset == kStage6StartLuaGateHelperOffset ||
       libroblox_offset == kStage6StartLuaGateHelperOffset + 1)) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    uint32_t phase = 0xffffffffu;
    uint64_t payload_first = 0;
    if (IsReadableMemoryRange(state + 0x138, sizeof(uint32_t))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    if (IsReadableMemoryRange(payload, sizeof(uint64_t))) {
      payload_first = *reinterpret_cast<const uint64_t*>(payload);
    }

    char msg[560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] entered Stage6 StartLua gate helper off=0x%lx "
        "state=%p phase=0x%x payload=%p payload0=0x%llx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(state), phase, reinterpret_cast<void*>(payload),
        static_cast<unsigned long long>(payload_first));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      const uintptr_t pushed_rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) = pushed_rbp;
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp - sizeof(uintptr_t));
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaGateHelperOffset + 1);
      return;
    }
  }

  if (signo == SIGTRAP && g_current_stage >= 6 && libroblox_base != 0 &&
      (libroblox_offset == kStage6StartLuaDeepStartOffset ||
       libroblox_offset == kStage6StartLuaDeepStartOffset + 1)) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    uint32_t phase = 0xffffffffu;
    uint64_t payload_first = 0;
    if (IsReadableMemoryRange(state + 0x138, sizeof(uint32_t))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    if (IsReadableMemoryRange(payload, sizeof(uint64_t))) {
      payload_first = *reinterpret_cast<const uint64_t*>(payload);
    }
    char msg[520];
    int len = snprintf(msg, sizeof(msg),
                       "  [trace] entered Stage6 deep StartLua off=0x%lx "
                       "state=%p phase=0x%x payload=%p payload0=0x%llx\n",
                       static_cast<unsigned long>(libroblox_offset),
                       reinterpret_cast<void*>(state), phase,
                       reinterpret_cast<void*>(payload),
                       static_cast<unsigned long long>(payload_first));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      const uintptr_t pushed_rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) = pushed_rbp;
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp - sizeof(uintptr_t));
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaDeepStartOffset + 1);
      return;
    }
  }

  if (signo == SIGTRAP && instruction[0] == 0xcc) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] = "  [patch] skipped int3 trap in startup path\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 1;
    return;
  }

  // SI_KERNEL SIGTRAP commonly follows a CET shadow-stack return mismatch.
  // Use a thread-local recovery target when one is armed.
  if (signo == SIGTRAP && info && info->si_code == SI_KERNEL &&
      g_current_stage >= 6) {
    if (libroblox_base != 0 &&
        libroblox_offset >= kV2StartAppCallbackTailStartOffset &&
        libroblox_offset <= kV2StartAppCallbackTailEndOffset) {
      char msg[300];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [patch] SI_KERNEL SIGTRAP in StartApp callback tail "
                   "off=0x%lx; exiting internal thread\n",
                   static_cast<unsigned long>(libroblox_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      syscall(SYS_exit, 0);
      return;
    }
    if (g_init_with_params_recovery_in_progress != 0) {
      g_init_with_params_recovery_in_progress = 0;
      const char msg[] =
          "  [patch] SI_KERNEL SIGTRAP recovered via InitWithParams jmp\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_init_with_params_jmp_buf, 1);
    }
    if (g_start_lua_app_dm_recovery_in_progress != 0) {
      g_start_lua_app_dm_recovery_in_progress = 0;
      const char msg[] =
          "  [patch] SI_KERNEL SIGTRAP recovered via StartLuaAppDM jmp\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
    }
    if (g_start_app_with_params_recovery_in_progress != 0) {
      g_start_app_with_params_recovery_in_progress = 0;
      const char msg[] =
          "  [patch] SI_KERNEL SIGTRAP recovered via StartAppWithParams jmp\n";
      write(2, msg, sizeof(msg) - 1);
      siglongjmp(g_start_app_with_params_jmp_buf, 1);
    }
    // Roblox may wait on this thread, so exiting it can hang the engine.
    const char msg[] =
        "  [patch] SI_KERNEL SIGTRAP: no recovery, skipping instruction\n";
    write(2, msg, sizeof(msg) - 1);
    // SI_KERNEL leaves RIP on the instruction that has not run yet.
    ucontext->uc_mcontext.gregs[REG_RIP] += 1;
    return;
  }

  if (instruction[0] == 0x49 && instruction[1] == 0x89 &&
      instruction[2] == 0x47 && instruction[3] == 0xf8) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] remapped R15 base for mov %rax,-0x8(%r15) in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R15] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (instruction[0] == 0x4e && instruction[1] == 0x89 &&
      instruction[2] == 0x24 && instruction[3] == 0xef) {
    if (static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]) ==
        g_stage5_last_fallback_rip) {
      if (g_skipped_headless_null_writes == 0) {
        const char msg[] =
            "  [patch] suppressed repeated Stage5 store fallback retry\n";
        write(2, msg, sizeof(msg) - 1);
      }
      ucontext->uc_mcontext.gregs[REG_RIP] += 4;
      return;
    }
    g_stage5_last_fallback_rip = ucontext->uc_mcontext.gregs[REG_RIP];
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] normalized mov [r15,r13*8,r12] StoreBase in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] = 0;
    ucontext->uc_mcontext.gregs[REG_R15] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (instruction[0] == 0x48 && instruction[1] == 0x89 &&
      instruction[2] == 0x51 && instruction[3] == 0x08) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] remapped RCX base for store [rcx+8],rdx in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage == 5 && info && info->si_addr == nullptr &&
      instruction[0] == 0x4a && instruction[1] == 0x8b &&
      instruction[2] == 0x04 && instruction[3] == 0xf0) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped null indexed JNI array load in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 5 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    if (TryHandleStage5MisalignedAtomic(ucontext, instruction)) {
      return;
    }
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0xf0 &&
      (instruction[1] == 0x48 || instruction[1] == 0x4a) &&
      instruction[2] == 0x0f && instruction[3] == 0xb1 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < kStage5LowAddressThreshold) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected low-address lock-cmpxchg base in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0xf0 &&
      (reinterpret_cast<uintptr_t>(info->si_addr) <
           kStage5LowAddressThreshold ||
       info->si_code == SEGV_ACCERR)) {
    size_t skip_len = 0;
    if ((instruction[1] & 0xf0) == 0x40 && instruction[2] == 0x0f &&
        (instruction[3] == 0xb1 || instruction[3] == 0xc1)) {
      skip_len = 6;
    } else if ((instruction[1] & 0xf0) == 0x40 &&
               (instruction[2] == 0x09 || instruction[2] == 0x0b ||
                instruction[2] == 0x21 || instruction[2] == 0x29)) {
      skip_len = 6;
    } else if ((instruction[1] & 0xf0) == 0x40 && instruction[2] == 0xff) {
      skip_len = 7;
    }
    if (skip_len != 0) {
      if (g_skipped_headless_null_writes == 0) {
        const char msg[] =
            "  [patch] skipped generic Stage6 protected/low atomic op\n";
        write(2, msg, sizeof(msg) - 1);
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RIP] += static_cast<greg_t>(skip_len);
      return;
    }
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x48 && instruction[2] == 0x0f &&
      instruction[3] == 0xb1 && instruction[4] == 0x0c &&
      instruction[5] == 0xf2 && info->si_code == SEGV_ACCERR) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 protected lock-cmpxchg retry loop\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = ucontext->uc_mcontext.gregs[REG_RCX];
    ucontext->uc_mcontext.gregs[REG_RIP] += 8;
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x4b && instruction[2] == 0x09 &&
      instruction[3] == 0x44 && instruction[4] == 0xf2 &&
      instruction[5] == 0x40 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 low-address atomic bitset write\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 6;
    return;
  }

  if (g_current_stage >= 6 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x4d && instruction[2] == 0x0f &&
      instruction[3] == 0xb1 && instruction[4] == 0x7a &&
      instruction[5] == 0x08 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage6 low-address atomic header CAS\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = ucontext->uc_mcontext.gregs[REG_R15];
    ucontext->uc_mcontext.gregs[REG_RIP] += 6;
    return;
  }

  if (g_current_stage >= 5 && rax == 0 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x3c &&
      instruction[3] == 0x10 && instruction[4] == 0x48 &&
      instruction[5] == 0x85 && instruction[6] == 0xff) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped null base-pointer JNI dereference in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    return;
  }

  if (g_current_stage >= 5 && rax == 0 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x3c &&
      instruction[3] == 0x08 && instruction[4] == 0x48 &&
      instruction[5] == 0x85 && instruction[6] == 0xff) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped null base-pointer JNI dereference in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    return;
  }

  if (g_current_stage >= 5 && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x71 &&
      instruction[3] == 0x30 && instruction[4] == 0x48 &&
      instruction[5] == 0xff && instruction[6] == 0xc6 &&
      instruction[7] == 0x48 && instruction[8] == 0x89 &&
      instruction[9] == 0x71 && instruction[10] == 0x30) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] remapped nil rcx+0x30 dereference in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage >= 5 && instruction[0] == 0x88 &&
      instruction[1] == 0x11 && instruction[2] == 0x48 &&
      instruction[3] == 0xff && instruction[4] == 0xc9 &&
      instruction[5] == 0x48 && instruction[6] == 0x39 &&
      instruction[7] == 0xc1 && instruction[8] == 0x77 &&
      instruction[9] == 0xf0 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage6 low-RCX byte write to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage >= 5 && info && rax == 0 && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x40 &&
      instruction[3] == 0x18 && info->si_addr != nullptr &&
      reinterpret_cast<uintptr_t>(info->si_addr) == 0x18) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped null base-pointer RAX+0x18 dereference in "
          "JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x13 &&
      instruction[3] == 0x48 && instruction[4] == 0x89 &&
      instruction[5] == 0x50 && instruction[6] == 0x08 &&
      instruction[7] == 0x66 && instruction[8] == 0xff &&
      instruction[9] == 0x40 && instruction[10] == 0x10) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] remapped invalid JNI_OnLoad rbx load to fallback "
          "scratch\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0x41 &&
      instruction[1] == 0xc6 && instruction[2] == 0x47 &&
      instruction[3] == 0x16 && instruction[4] == 0x00) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] remapped invalid JNI_OnLoad r15 byte store to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R15] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }

  if (g_current_stage >= 5 && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x3c &&
      instruction[3] == 0x08 && instruction[4] == 0x48 &&
      instruction[5] == 0x85 && instruction[6] == 0xff &&
      instruction[7] == 0x74 && instruction[8] == 0x1f) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected Stage5 rax+rcx object read to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[3] == 0x08 &&
      instruction[4] == 0x48) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped null/invalid base-pointer dereference in "
          "JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 5 && instruction[0] == 0x49 &&
      instruction[1] == 0x8b && instruction[2] == 0x3f &&
      instruction[3] == 0x48 && instruction[4] == 0x85 &&
      instruction[5] == 0xff && instruction[6] == 0x74 &&
      instruction[7] == 0x44 && instruction[8] == 0x8a &&
      instruction[9] == 0x4f && instruction[10] == 0x16 &&
      instruction[11] == 0x84 && instruction[12] == 0xc9 &&
      instruction[13] == 0x74 && instruction[14] == 0x3d) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped Stage5 r15 entry inspection in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x4c;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x10 &&
      instruction[3] == 0x48 && instruction[4] == 0x89 &&
      instruction[5] == 0x51 && instruction[6] == 0x08 &&
      instruction[7] == 0x66 && instruction[8] == 0xff &&
      instruction[9] == 0x41 && instruction[10] == 0x10) {
    uintptr_t current_rax =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    bool should_skip =
        (current_rax < 4096) || ((current_rax & 0xffff) == current_rax);
    if (should_skip) {
      if (g_skipped_headless_null_writes == 0) {
        const char msg[] =
            "  [patch] skipped invalid JNI_OnLoad rcx/rax memcpy sequence\n";
        write(2, msg, sizeof(msg) - 1);
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RIP] += 0x0b;
      return;
    }
  }

  if (g_current_stage == 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x89 && instruction[4] == 0x48 &&
      instruction[5] == 0x85) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped store through invalid base pointer in "
          "JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x48 && instruction[2] == 0x0f &&
      instruction[3] == 0xc1 && instruction[4] == 0x90 &&
      instruction[5] == 0xf0 && instruction[6] == 0x07 &&
      instruction[7] == 0x00 && instruction[8] == 0x00 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) == 0) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped lock-xadd through invalid base pointer in "
          "JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x23;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x48 && instruction[2] == 0x0f &&
      instruction[3] == 0xc1 && instruction[4] == 0x51 &&
      instruction[5] == 0x10 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped lock-xadd via short TLS pointer in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x10;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x48 && instruction[2] == 0x0f &&
      instruction[3] == 0xc1 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped low-address lock-xadd in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x10;
    return;
  }

  if (g_current_stage >= 5 && info && instruction[0] == 0xf0 &&
      instruction[1] == 0x48 && instruction[2] == 0xff &&
      instruction[3] == 0x80 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      instruction[4] == 0xe8 && instruction[5] == 0x08 &&
      instruction[6] == 0x00 && instruction[7] == 0x00 &&
      instruction[8] == 0xe8) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped lock-dec/atomic low-address op in JNI_OnLoad\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 0x0d;
    return;
  }

  if (IsHeadlessMode() && rax == 0 && info && info->si_addr == nullptr &&
      instruction[0] == 0x66 && instruction[1] == 0x89 &&
      instruction[2] == 0x30) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] = "  [patch] skipped headless null UTF-16 write\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RIP] += 3;
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x4c &&
      instruction[1] == 0x8b && instruction[2] == 0x6f &&
      instruction[3] == 0x08 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped low-address hash table bucket count read\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R13] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x43 &&
      instruction[3] == 0x18 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped low-address hash table item count read\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x8b && instruction[2] == 0x3b &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected low-address hash table object to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x89 && instruction[2] == 0x07 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected null object initialisation to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x4c &&
      instruction[1] == 0x8b && instruction[2] == 0x3f &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected low-address object field read to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x4c &&
      instruction[1] == 0x03 && instruction[2] == 0x7b &&
      instruction[3] == 0x18 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected low-address object size read to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x48 &&
      instruction[1] == 0x3b && instruction[2] == 0x43 &&
      instruction[3] == 0x18 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096 &&
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected low-address object metadata compare to "
          "fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RBX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 6 && info && instruction[0] == 0xf6 &&
      instruction[1] == 0x00 && instruction[2] == 0x01 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected null tagged string object to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    g_stage5_fallback_region[0] = 0;
    *reinterpret_cast<uint64_t*>(g_stage5_fallback_region + 8) = 0;
    *reinterpret_cast<uint64_t*>(g_stage5_fallback_region + 16) = 0;
    ucontext->uc_mcontext.gregs[REG_RAX] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 6 && info && instruction[0] == 0x80 &&
      instruction[1] == 0x7f && instruction[2] == 0x34 &&
      instruction[3] == 0x00) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] redirected invalid Stage6 option object to fallback\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    g_stage5_fallback_region[0x34] = 0;
    ucontext->uc_mcontext.gregs[REG_RDI] =
        reinterpret_cast<greg_t>(g_stage5_fallback_region);
    return;
  }
  if (g_current_stage >= 6 && info && instruction[0] == 0x49 &&
      instruction[1] == 0x8b && instruction[2] == 0x0c &&
      instruction[3] == 0xf7 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped low-address Stage6 bitset table read\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RCX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  if (g_current_stage >= 6 && info && instruction[0] == 0x49 &&
      instruction[1] == 0x8b && instruction[2] == 0x42 &&
      instruction[3] == 0x08 &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] skipped low-address Stage6 bitset header read\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  if (g_current_stage >= 5 && info && instruction[0] == 0x44 &&
      instruction[1] == 0x0f && instruction[2] == 0xb6 &&
      instruction[3] == 0x37) {
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] treated invalid byte-tagged object as empty\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    ucontext->uc_mcontext.gregs[REG_R14] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] += 4;
    return;
  }
  uintptr_t rdi = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
  if (IsHeadlessMode() && rdi < 4096 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) < 4096) {
    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (stack && *stack != 0) {
      if (g_skipped_headless_null_writes == 0) {
        const char msg[] = "  [patch] skipped headless null memory copy\n";
        write(2, msg, sizeof(msg) - 1);
      }
      ++g_skipped_headless_null_writes;
      ucontext->uc_mcontext.gregs[REG_RAX] =
          static_cast<greg_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(*stack);
      ucontext->uc_mcontext.gregs[REG_RSP] += 8;
      return;
    }
  }
  uintptr_t fault_rip =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
  if (g_current_stage >= 6 && info &&
      reinterpret_cast<uintptr_t>(info->si_addr) == fault_rip &&
      (info->si_code == SEGV_ACCERR || info->si_code == SEGV_MAPERR)) {
    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    uintptr_t return_address = stack ? *stack : 0;
    auto* frame =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RBP]);
    uintptr_t frame_return_address = frame ? frame[1] : 0;
    Dl_info return_info;
    auto is_roblox_return = [&](uintptr_t address) {
      return address != 0 &&
             ((dladdr(reinterpret_cast<void*>(address), &return_info) != 0 &&
               return_info.dli_fname != nullptr &&
               std::strstr(return_info.dli_fname, "libroblox.so") != nullptr) ||
              (g_libroblox_base != 0 && address >= g_libroblox_base &&
               address < g_libroblox_base + 0x08000000));
    };
    if (!is_roblox_return(return_address) &&
        is_roblox_return(frame_return_address)) {
      return_address = frame_return_address;
    }
    const bool returns_to_roblox = is_roblox_return(return_address);
    if (returns_to_roblox) {
      if (IsReadableMemoryRange(return_address, 1) &&
          *reinterpret_cast<const unsigned char*>(return_address) == 0xcc) {
        ++return_address;
      }
      uintptr_t return_offset =
          (g_libroblox_base != 0 && return_address >= g_libroblox_base &&
           return_address < g_libroblox_base + 0x08000000)
              ? return_address - g_libroblox_base
              : 0;
      uintptr_t frame_return_offset =
          (g_libroblox_base != 0 && frame_return_address >= g_libroblox_base &&
           frame_return_address < g_libroblox_base + 0x08000000)
              ? frame_return_address - g_libroblox_base
              : 0;
      char msg[512];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] skipped erroneous Stage6 heap function-pointer call "
          "rip=%p return_off=0x%lx frame_return_off=0x%lx\n",
          reinterpret_cast<void*>(fault_rip),
          static_cast<unsigned long>(return_offset),
          static_cast<unsigned long>(frame_return_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ucontext->uc_mcontext.gregs[REG_RAX] = 0;
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(return_address);
      ucontext->uc_mcontext.gregs[REG_RSP] += 8;
      return;
    }
  }
  uintptr_t fault_rsi =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
  if (g_current_stage >= 6 && info && info->si_addr == nullptr &&
      fault_rsi == 0 && module_name && std::strstr(module_name, "libc.so")) {
    const char msg[] =
        "  [patch] redirected Stage6 libc null source to empty string\n";
    write(2, msg, sizeof(msg) - 1);
    ucontext->uc_mcontext.gregs[REG_RSI] =
        reinterpret_cast<greg_t>(g_empty_c_string);
    return;
  }
  const char* signal_name = "UNKNOWN";
  switch (signo) {
    case SIGSEGV:
      signal_name = "SIGSEGV";
      break;
    case SIGILL:
      signal_name = "SIGILL";
      break;
    case SIGABRT:
      signal_name = "SIGABRT";
      break;
    case SIGBUS:
      signal_name = "SIGBUS";
      break;
    case SIGFPE:
      signal_name = "SIGFPE";
      break;
    case SIGTRAP:
      signal_name = "SIGTRAP";
      break;
  }

  char msg[512];
  int message_len = snprintf(
      msg, sizeof(msg),
      "  [crash] stage=%d signal=%s (%d) module=%s symbol=%s(%p) "
      "si_code=%d si_addr=%p\n",
      static_cast<int>(g_current_stage), signal_name, signo, module_name,
      symbol_name, symbol_addr, (info != nullptr ? info->si_code : 0),
      (info != nullptr ? info->si_addr : nullptr));
  if (message_len > 0) {
    write(2, msg, static_cast<size_t>(message_len));
  }

  char instr_msg[160];
  int instr_len =
      snprintf(instr_msg, sizeof(instr_msg), "  [crash] RIP bytes: ");
  if (instruction_readable) {
    for (int i = 0; i < 16; ++i) {
      instr_len += snprintf(instr_msg + instr_len,
                            sizeof(instr_msg) - static_cast<size_t>(instr_len),
                            "%02x%s", instruction[i], i + 1 == 16 ? "\n" : " ");
    }
  } else {
    instr_len += snprintf(instr_msg + instr_len,
                          sizeof(instr_msg) - static_cast<size_t>(instr_len),
                          "<unreadable rip=%p>\n",
                          reinterpret_cast<void*>(instruction_address));
  }
  if (instr_len > 0) {
    write(2, instr_msg, static_cast<size_t>(instr_len));
  }

  int regs_message_len = snprintf(
      msg, sizeof(msg),
      "  [crash] stage=%d signal=%s (%d) si_code=%d si_addr=%p, "
      "RIP=%p RSP=%p RAX=%p RBX=%p RCX=%p RDX=%p RSI=%p RDI=%p RBP=%p\n",
      static_cast<int>(g_current_stage), signal_name, signo,
      (info != nullptr ? info->si_code : 0),
      (info != nullptr ? info->si_addr : nullptr),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSP]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
      reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBP]));
  if (regs_message_len > 0) {
    write(2, msg, static_cast<size_t>(regs_message_len));
  }

  PrintAddressMapForRip(
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]));
  const char bt_prefix[] = "  [crash] context backtrace:\n";
  write(2, bt_prefix, sizeof(bt_prefix) - 1);
  PrintContextBacktrace(ucontext, "    ");
  PrintBacktraceNoSig("  [crash] backtrace (async symbols):\n");
#else
  (void)info;
  (void)context;
#endif
  signal(signo, SIG_DFL);
  raise(signo);
}

void InstallHeadlessSegvHandler() {
  if (IsDisabled("MOCKTAIL_HEADLESS_SIGSEGV_GUARDS")) {
    return;
  }

  struct sigaction action;
  std::memset(&action, 0, sizeof(action));
  action.sa_sigaction = HeadlessSegvHandler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGSEGV, &action, nullptr);
  sigaction(SIGILL, &action, nullptr);
  sigaction(SIGABRT, &action, nullptr);
  sigaction(SIGBUS, &action, nullptr);
  sigaction(SIGFPE, &action, nullptr);
  sigaction(SIGTRAP, &action, nullptr);

  struct sigaction diag_action;
  std::memset(&diag_action, 0, sizeof(diag_action));
  diag_action.sa_sigaction = DumpThreadPcSignalHandler;
  sigemptyset(&diag_action.sa_mask);
  diag_action.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGUSR1, &diag_action, nullptr);
}

}  // namespace mocktail::legacy::internal
