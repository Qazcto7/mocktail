#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>

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

bool TryHandleStage5LowAddressAtomic(ucontext_t* ucontext,
                                     unsigned char* instruction) {
  if (!ucontext || !instruction) {
    return false;
  }

  int idx = 0;
  bool lock_prefix = false;
  uint8_t rex = 0;
  if (instruction[idx] == 0xf0) {
    lock_prefix = true;
    ++idx;
  }
  if ((instruction[idx] & 0xF0) == 0x40) {
    rex = instruction[idx];
    ++idx;
  }

  if (instruction[idx] != 0x0f &&
      !(instruction[idx] == 0xff && (instruction[idx + 1] & 0x38) == 0x00) &&
      !(lock_prefix && instruction[idx] == 0x48 &&
        (instruction[idx + 1] == 0x0f) &&
        (instruction[idx + 2] == 0xc1 || instruction[idx + 2] == 0xb1)) &&
      !(lock_prefix && instruction[idx] == 0x48 &&
        instruction[idx + 1] == 0xff && instruction[idx + 2] == 0x80)) {
    return false;
  }

  uint8_t opcode = instruction[idx];
  int modrm_offset = -1;
  if (opcode == 0x0f) {
    modrm_offset = idx + 2;
  } else {
    modrm_offset = idx + 1;
  }

  uint8_t modrm = instruction[modrm_offset];
  int mod = (modrm >> 6);
  bool memory = mod != 3;
  if (!memory) {
    return false;
  }

  int rm = modrm & 0x07;
  int base_reg = rm + ((rex & 0x01) ? 8 : 0);
  if (rm == 4) {
    uint8_t sib = instruction[modrm_offset + 1];
    int sib_base = sib & 0x07;
    if (sib_base == 5 && mod == 0) {
      return false;
    }
    base_reg = sib_base + ((rex & 0x01) ? 8 : 0);
  }

  auto* base_slot = Stage5RegisterSlotById(ucontext, base_reg);
  if (base_slot == nullptr) {
    return false;
  }

  uintptr_t base = static_cast<uintptr_t>(*base_slot);
  if (base == 0 || base >= kStage5LowAddressThreshold) {
    return false;
  }

  *base_slot = reinterpret_cast<greg_t>(&g_stage5_fallback_region[0]);
  if (g_skipped_headless_null_writes == 0) {
    const char msg[] =
        "  [patch] remapped low-base Stage5 memory op to fallback scratch\n";
    write(2, msg, sizeof(msg) - 1);
  }
  ++g_skipped_headless_null_writes;
  return true;
}

bool TryHandleStage5MisalignedAtomic(ucontext_t* ucontext,
                                     unsigned char* instruction) {
  // Some SIGSEGVs arrive in the middle of a lock-prefixed atomic sequence,
  // so we scan a few bytes back and realign RIP to a valid known prefix.
  for (int shift = 1; shift <= 8; ++shift) {
    const unsigned char* candidate = instruction - shift;
    if (candidate[0] != 0xF0) {
      continue;
    }

    if (candidate[1] == 0x48 && candidate[2] == 0x0f &&
        (candidate[3] == 0xb1 || candidate[3] == 0xc1 || candidate[3] == 0xff ||
         candidate[3] == 0x01)) {
      ucontext->uc_mcontext.gregs[REG_RIP] =
          reinterpret_cast<greg_t>(const_cast<unsigned char*>(candidate));
      if (g_skipped_headless_null_writes == 0) {
        const char msg[] =
            "  [patch] realigned RIP to lock-atomic start in Stage 5\n";
        write(2, msg, sizeof(msg) - 1);
      }
      ++g_skipped_headless_null_writes;
      return true;
    }
  }

  // Special-case the recurring pattern observed in logs where a short tail
  // leaks into the next lock-atomic block.
  if (instruction[0] == 0x08 && instruction[1] == 0x00 &&
      instruction[2] == 0x00 && instruction[3] == 0x48 &&
      instruction[4] == 0x39 && instruction[5] == 0xd0 &&
      instruction[6] == 0x7d && instruction[7] == 0x0b &&
      instruction[8] == 0xf0 && instruction[9] == 0x48 &&
      instruction[10] == 0x0f && instruction[11] == 0xb1 &&
      (instruction[12] == 0x91 || instruction[12] == 0x11 ||
       instruction[12] == 0x90)) {
    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(reinterpret_cast<uintptr_t>(instruction) + 8);
    if (g_skipped_headless_null_writes == 0) {
      const char msg[] =
          "  [patch] corrected mid-instruction Stage5 lock op offset\n";
      write(2, msg, sizeof(msg) - 1);
    }
    ++g_skipped_headless_null_writes;
    return true;
  }

  return false;
}

bool TryHandleStage6StartLuaTraceTrap(int signo, uintptr_t libroblox_base,
                                      uintptr_t libroblox_offset,
                                      ucontext_t* ucontext) {
  if (signo != SIGTRAP || g_current_stage < 6 || libroblox_base == 0 ||
      ucontext == nullptr) {
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

  if ((libroblox_offset == kStage6StartLuaSyntheticInstanceUpdateCallOffset ||
       libroblox_offset ==
           kStage6StartLuaSyntheticInstanceUpdateCallOffset + 1) &&
      IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_SYNTHETIC_INSTANCE_"
                "SOURCE")) {
    const uintptr_t out_pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t instance =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t table =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t owner =
        table >= 0x1c8 ? table - static_cast<uintptr_t>(0x1c8) : 0;
    const uintptr_t owner_ref = ReadPointerIfReadable(owner + 0x10);
    bool wrote_owner_pair = false;
    if (out_pair >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(out_pair, 2 * sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(out_pair))) {
      *reinterpret_cast<uintptr_t*>(out_pair + 0x00) = 0;
      *reinterpret_cast<uintptr_t*>(out_pair + 0x08) = 0;
    }
    if (owner >= kStage5LowAddressThreshold &&
        owner_ref >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(owner + 0xe0, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(owner + 0xd8))) {
      *reinterpret_cast<uintptr_t*>(owner + 0xd8) = owner;
      *reinterpret_cast<uintptr_t*>(owner + 0xe0) = owner_ref;
      wrote_owner_pair = true;
    }
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua synthetic Instance update skipped "
        "off=0x%lx instance=%p table=%p owner=%p owner_ref=%p "
        "wrote_owner_pair=%d out_pair=%p out_fields{%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(instance), reinterpret_cast<void*>(table),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(owner_ref),
        wrote_owner_pair ? 1 : 0, reinterpret_cast<void*>(out_pair),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_pair + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_pair + 0x08)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaSyntheticInstanceUpdateReturnOffset);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResult20LookupTreeReadOffset ||
      libroblox_offset == kStage6StartLuaResult20LookupTreeReadOffset + 1) {
    const uintptr_t out =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t lookup_base =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t key =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t original_tree = ReadPointerIfReadable(lookup_base + 0xe8);
    const uintptr_t lookup_owner =
        lookup_base >= 0x1c8 ? lookup_base - 0x1c8 : 0;
    const uintptr_t target_ref = ReadPointerIfReadable(lookup_owner + 0x10);
    const bool lookup_owner_pair_readable =
        IsReadableMemoryRange(lookup_owner + 0x08, sizeof(uintptr_t)) &&
        IsReadableMemoryRange(lookup_owner + 0x10, sizeof(uintptr_t));
    const bool tree_unreadable =
        original_tree < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(original_tree + 0x20, 0x18);
    uintptr_t tree = original_tree;
    const bool forced_target_pair =
        tree_unreadable &&
        IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_TARGET_"
            "PAIR") &&
        lookup_owner >= kStage5LowAddressThreshold &&
        target_ref >= kStage5LowAddressThreshold && lookup_owner_pair_readable;
    const bool forced_empty =
        !forced_target_pair && tree_unreadable &&
        IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_EMPTY");
    if (forced_target_pair) {
      std::memset(g_stage6_start_lua_result20_lookup_node_scratch, 0,
                  sizeof(g_stage6_start_lua_result20_lookup_node_scratch));
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_result20_lookup_node_scratch + 0x20) = key;
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_result20_lookup_node_scratch + 0x28) =
          lookup_owner;
      *reinterpret_cast<uintptr_t*>(
          g_stage6_start_lua_result20_lookup_node_scratch + 0x30) = target_ref;
      tree = reinterpret_cast<uintptr_t>(
          g_stage6_start_lua_result20_lookup_node_scratch);
    } else if (forced_empty) {
      tree = 0;
    }
    static volatile sig_atomic_t result20_lookup_logs = 0;
    if (result20_lookup_logs < 32) {
      char msg[2200];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua result20 lookup tree-read off=0x%lx "
          "out=%p lookup_base=%p lookup_owner=%p key=%p tree=%p "
          "effective_tree=%p tree_unreadable=%d forced_target_pair=%d "
          "forced_empty=%d owner_pair_readable=%d target_pair{%p,%p} "
          "lookup_slots{e0=%p e8=%p f0=%p f8=%p 100=%p 108=%p} "
          "target_slots{8=%p 10=%p 158=%p 1a0=%p 1b8=%p 1c8=%p 228=%p "
          "438=%p} "
          "node_fields{0=%p 8=%p 20=%p 28=%p 30=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(out), reinterpret_cast<void*>(lookup_base),
          reinterpret_cast<void*>(lookup_owner), reinterpret_cast<void*>(key),
          reinterpret_cast<void*>(original_tree), reinterpret_cast<void*>(tree),
          tree_unreadable ? 1 : 0, forced_target_pair ? 1 : 0,
          forced_empty ? 1 : 0, lookup_owner_pair_readable ? 1 : 0,
          reinterpret_cast<void*>(lookup_owner),
          reinterpret_cast<void*>(target_ref),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0xe0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0xe8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0xf0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0xf8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0x100)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_base + 0x108)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x158)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x1a0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x1b8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x1c8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x228)),
          reinterpret_cast<void*>(ReadPointerIfReadable(lookup_owner + 0x438)),
          reinterpret_cast<void*>(ReadPointerIfReadable(original_tree + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(original_tree + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(original_tree + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(original_tree + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(original_tree + 0x30)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++result20_lookup_logs;
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(tree);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        (forced_empty ? kStage6StartLuaResult20LookupEmptyReturnOffset
                      : kStage6StartLuaResult20LookupTreeReadOffset + 7));
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResult20SourceBuilderReturnOffset ||
      libroblox_offset ==
          kStage6StartLuaResult20SourceBuilderReturnOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t out =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t local_pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t source_context = ReadPointerIfReadable(rbp - 0x28);
    const uintptr_t source_value = ReadPointerIfReadable(source_context);
    const uint32_t source_tag = ReadU32IfReadable(source_context + 0x08);
    const uintptr_t local_object = ReadPointerIfReadable(local_pair);
    const uintptr_t local_ref = ReadPointerIfReadable(local_pair + 0x08);
    char local_class[96] = {};
    ReadLibcxxStringPreview(ReadPointerIfReadable(local_object + 0xb0),
                            local_class, sizeof(local_class));
    char msg[1200];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua result20 source builder return off=0x%lx "
        "out=%p out_before{%p,%p} local_pair=%p local{%p,%p} "
        "local_class='%s' source_context=%p source{%p,0x%x} "
        "caller_return=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(out),
        reinterpret_cast<void*>(ReadPointerIfReadable(out + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out + 0x08)),
        reinterpret_cast<void*>(local_pair),
        reinterpret_cast<void*>(local_object),
        reinterpret_cast<void*>(local_ref), local_class,
        reinterpret_cast<void*>(source_context),
        reinterpret_cast<void*>(source_value), source_tag,
        reinterpret_cast<void*>(
            ReadPointerIfReadable(rbp + sizeof(uintptr_t))));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(local_ref);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResult20SourceBuilderReturnOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResult20SourceParseReturnOffset ||
      libroblox_offset == kStage6StartLuaResult20SourceParseReturnOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t out =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t guard_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t source_value = ReadPointerIfReadable(rbp - 0x28);
    const uint32_t source_tag = ReadU32IfReadable(rbp - 0x20);
    uintptr_t out_object = ReadPointerIfReadable(out + 0x00);
    uintptr_t out_ref = ReadPointerIfReadable(out + 0x08);
    char out_class[96] = {};
    ReadLibcxxStringPreview(ReadPointerIfReadable(out_object + 0xb0), out_class,
                            sizeof(out_class));
    uintptr_t synthetic_object = 0;
    bool synthetic_overrode = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_SYNTHETIC_INSTANCE_"
                  "SOURCE") &&
        std::strcmp(out_class, "Instance") != 0 &&
        IsReadableMemoryRange(out, 2 * sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(out))) {
      synthetic_object = PrepareStage6StartLuaSyntheticInstanceSource(
          source_value, "result20 source parse");
      if (synthetic_object >= kStage5LowAddressThreshold) {
        out_object = synthetic_object;
        out_ref = reinterpret_cast<uintptr_t>(
            g_stage6_start_lua_synthetic_instance_control_block);
        *reinterpret_cast<uintptr_t*>(out + 0x00) = out_object;
        *reinterpret_cast<uintptr_t*>(out + 0x08) = out_ref;
        std::memset(out_class, 0, sizeof(out_class));
        ReadLibcxxStringPreview(ReadPointerIfReadable(out_object + 0xb0),
                                out_class, sizeof(out_class));
        synthetic_overrode = true;
      }
    }
    char msg[1200];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua result20 source parse return off=0x%lx "
        "out=%p out{%p,%p} out_class='%s' source{%p,0x%x} "
        "synthetic_instance=%d synthetic_object=%p "
        "guard_slot=%p guard=%p caller_return=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(out), reinterpret_cast<void*>(out_object),
        reinterpret_cast<void*>(out_ref), out_class,
        reinterpret_cast<void*>(source_value), source_tag,
        synthetic_overrode ? 1 : 0, reinterpret_cast<void*>(synthetic_object),
        reinterpret_cast<void*>(guard_slot),
        reinterpret_cast<void*>(ReadPointerIfReadable(guard_slot)),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(rbp + sizeof(uintptr_t))));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] =
        static_cast<greg_t>(ReadPointerIfReadable(guard_slot));
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResult20SourceParseReturnOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverTaskCreateOffset ||
      libroblox_offset == kStage6StartLuaResolverTaskCreateOffset + 1) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t out_local =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t queue_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t arg_rcx =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t arg_r8 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R8]);
    const uintptr_t arg_r9 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R9]);
    const uintptr_t stack0 = ReadPointerIfReadable(rsp + 0x08);
    const uintptr_t stack1 = ReadPointerIfReadable(rsp + 0x10);
    const uintptr_t stack2 = ReadPointerIfReadable(rsp + 0x18);
    const uintptr_t stack3 = ReadPointerIfReadable(rsp + 0x20);
    const uintptr_t stack4 = ReadPointerIfReadable(rsp + 0x28);
    const uintptr_t stack5 = ReadPointerIfReadable(rsp + 0x30);
    static volatile sig_atomic_t resolver_task_create_logs = 0;
    if (resolver_task_create_logs < 16) {
      char msg[2200];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver task create off=0x%lx "
          "task=%p task_fields{48=%p 78=%p} out_local=%p "
          "out_local_fields{%p,%p} queue_slot=%p queue_slot_value=%p "
          "arg_ptrs{rcx=%p r8=%p r9=%p stack=%p,%p,%p,%p,%p,%p} "
          "arg_values{rcx=%p r8=%p r9=%p stack=%p,%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x78)),
          reinterpret_cast<void*>(out_local),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_local + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_local + 0x08)),
          reinterpret_cast<void*>(queue_slot),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue_slot)),
          reinterpret_cast<void*>(arg_rcx), reinterpret_cast<void*>(arg_r8),
          reinterpret_cast<void*>(arg_r9), reinterpret_cast<void*>(stack0),
          reinterpret_cast<void*>(stack1), reinterpret_cast<void*>(stack2),
          reinterpret_cast<void*>(stack3), reinterpret_cast<void*>(stack4),
          reinterpret_cast<void*>(stack5),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg_rcx)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg_r8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg_r9)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack1)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack2)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack3)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack4)),
          reinterpret_cast<void*>(ReadPointerIfReadable(stack5)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_task_create_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverTaskCreateOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverBuildOffset ||
      libroblox_offset == kStage6StartLuaResolverBuildOffset + 1) {
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t out_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t target_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t result20 = ReadPointerIfReadable(target_result + 0x20);
    const uintptr_t resolve_global =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    static volatile sig_atomic_t resolver_build_logs = 0;
    if (resolver_build_logs < 16) {
      char msg[1520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver build off=0x%lx "
          "out_slot=%p current_out=%p target_result=%p "
          "result_fields{%p,%p,%p,%p} "
          "result20_fields{%p,%p,%p,%p,%p,%p} resolve_global=%p "
          "r8=%p r9=%p stack_args{%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(out_slot),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_slot)),
          reinterpret_cast<void*>(target_result),
          reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x28)),
          reinterpret_cast<void*>(resolve_global),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9]),
          reinterpret_cast<void*>(ReadPointerIfReadable(rsp + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rsp + 0x10)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_build_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverBuildOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverAfterTaskBuildOffset ||
      libroblox_offset == kStage6StartLuaResolverAfterTaskBuildOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    const uintptr_t out_slot =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t task_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t target_result = ReadPointerIfReadable(rbp - 0x40);
    const uintptr_t resolve_global = ReadPointerIfReadable(rbp - 0x50);
    const uintptr_t callback_hint = ReadPointerIfReadable(rbp - 0x38);
    static volatile sig_atomic_t resolver_after_task_logs = 0;
    if (resolver_after_task_logs < 16) {
      const uintptr_t caller_out_slot = ReadPointerIfReadable(rbp - 0x48);
      char msg[1900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver after task-build off=0x%lx "
          "out_slot=%p out_fields{%p,%p} task_result=%p "
          "task_fields{28=%p 48=%p 68=%p 70=%p} "
          "caller_out=%p caller_out_fields{%p,%p,%p,%p} "
          "saved_args{target_result=%p resolve_global=%p callback_hint=%p "
          "mode=%p stack1=%p stack2=%p stack3=%p stack4=%p} "
          "rsp_before=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(out_slot),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_slot + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_slot + 0x08)),
          reinterpret_cast<void*>(task_result),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_result + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_result + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_result + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_result + 0x70)),
          reinterpret_cast<void*>(caller_out_slot),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(caller_out_slot + 0x00)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(caller_out_slot + 0x08)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(caller_out_slot + 0x10)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(caller_out_slot + 0x18)),
          reinterpret_cast<void*>(target_result),
          reinterpret_cast<void*>(resolve_global),
          reinterpret_cast<void*>(callback_hint),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x64)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x48)),
          reinterpret_cast<void*>(rsp));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_after_task_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(rsp + 0x30);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverAfterTaskBuildOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverQueueBindOffset ||
      libroblox_offset == kStage6StartLuaResolverQueueBindOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t resolver =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t out_pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    static volatile sig_atomic_t resolver_bind_logs = 0;
    if (resolver_bind_logs < 16) {
      char msg[1040];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver queue bind off=0x%lx "
          "queue=%p queue_count=0x%x resolver=%p task=%p "
          "queue_tail{d260=%p d268=%p d270=%p} "
          "task_fields{28=%p 48=%p 68=%p 70=%p} out_pair=%p "
          "out_pair_fields{%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue),
          IsReadableMemoryRange(queue + 0x64c, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(queue + 0x64c)
              : 0xffffffffu,
          reinterpret_cast<void*>(resolver), reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd260)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd268)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd270)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x70)),
          reinterpret_cast<void*>(out_pair),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_pair + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_pair + 0x08)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_bind_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(queue);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverQueueBindOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverQueuePickOffset ||
      libroblox_offset == kStage6StartLuaResolverQueuePickOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t resolver =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    static volatile sig_atomic_t resolver_queue_logs = 0;
    if (resolver_queue_logs < 16) {
      char msg[1120];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver queue pick off=0x%lx "
          "queue=%p queue_count=0x%x first_queue=%p "
          "first_queue_fields{28=%p 48=%p 60=%p 68=%p 70=%p} "
          "queue_tail{d260=%p d268=%p d270=%p} "
          "resolver=%p resolver_fields{%p,%p,%p} "
          "task=%p task_fields{28=%p 48=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue),
          IsReadableMemoryRange(queue + 0x64c, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(queue + 0x64c)
              : 0xffffffffu,
          reinterpret_cast<void*>(queue + 0x650),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650 + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650 + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650 + 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650 + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650 + 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd260)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd268)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0xd270)),
          reinterpret_cast<void*>(resolver),
          reinterpret_cast<void*>(ReadPointerIfReadable(resolver + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(resolver + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(resolver + 0x48)),
          reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_queue_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverQueuePickOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverQueuePickNullOffset ||
      libroblox_offset == kStage6StartLuaResolverQueuePickNullOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    uintptr_t flags = ReadPointerIfReadable(task + 0x48);
    bool seeded_queue = false;
    bool forced_task_queue_flag = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_TASK_QUEUE_FLAG") &&
        IsReadableMemoryRange(task + 0x48, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(task + 0x48))) {
      auto* task_flags = reinterpret_cast<uintptr_t*>(task + 0x48);
      if ((*task_flags & 0x2) == 0) {
        *task_flags |= 0x2;
        forced_task_queue_flag = true;
      }
      flags = *task_flags;
    }
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_QUEUE") &&
        IsReadableMemoryRange(queue + 0x64c, sizeof(uint32_t)) &&
        *reinterpret_cast<const uint32_t*>(queue + 0x64c) == 0 &&
        EnsureWritablePage(reinterpret_cast<void*>(queue + 0x64c))) {
      *reinterpret_cast<uint32_t*>(queue + 0x64c) = 1;
      seeded_queue = true;
    }
    static volatile sig_atomic_t resolver_null_logs = 0;
    if (resolver_null_logs < 16) {
      char msg[760];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver queue pick null-resolver "
          "off=0x%lx queue=%p queue_count=0x%x task=%p flags=%p "
          "flag_low=0x%x seeded_queue=%d forced_task_queue_flag=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue),
          IsReadableMemoryRange(queue + 0x64c, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(queue + 0x64c)
              : 0xffffffffu,
          reinterpret_cast<void*>(task), reinterpret_cast<void*>(flags),
          static_cast<unsigned int>(flags & 0xff), seeded_queue ? 1 : 0,
          forced_task_queue_flag ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_null_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(flags);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverQueuePickNullOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverQueuePickStoreOffset ||
      libroblox_offset == kStage6StartLuaResolverQueuePickStoreOffset + 1) {
    const uintptr_t selected =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t flags = ReadPointerIfReadable(task + 0x48);
    static volatile sig_atomic_t resolver_store_logs = 0;
    if (resolver_store_logs < 16) {
      char msg[860];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver queue pick store off=0x%lx "
          "selected=%p selected_fields{28=%p 48=%p 60=%p 68=%p 70=%p} "
          "task=%p flags_before=%p\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(selected),
          reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x70)),
          reinterpret_cast<void*>(task), reinterpret_cast<void*>(flags));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_store_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(flags);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverQueuePickStoreOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverSchedulerEntryOffset ||
      libroblox_offset == kStage6StartLuaResolverSchedulerEntryOffset + 1) {
    const uintptr_t queue =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t function_object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t timeout =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    static volatile sig_atomic_t resolver_scheduler_entry_logs = 0;
    if (resolver_scheduler_entry_logs < 16) {
      char msg[1180];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver scheduler entry off=0x%lx "
          "queue=%p task=%p task_fields{28=%p 48=%p} "
          "function_object=%p function_fields{%p,%p,%p,%p} timeout=0x%lx\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(queue), reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)),
          reinterpret_cast<void*>(function_object),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(function_object + 0x00)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(function_object + 0x08)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(function_object + 0x10)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(function_object + 0x18)),
          static_cast<unsigned long>(timeout));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_scheduler_entry_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverSchedulerEntryOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverSchedulerProcLoadOffset ||
      libroblox_offset == kStage6StartLuaResolverSchedulerProcLoadOffset + 1) {
    const uintptr_t proc_context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t task = ReadPointerIfReadable(rbp - 0x90);
    const uintptr_t task_flags = ReadPointerIfReadable(task + 0x48);
    const uintptr_t selected = task_flags & ~static_cast<uintptr_t>(0x3);
    uintptr_t current_proc = ReadPointerIfReadable(proc_context + 0x60);
    bool forced_scheduler_proc = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_SCHEDULER_PROC") &&
        selected != 0 && current_proc != selected && proc_context == selected) {
      current_proc = selected;
      forced_scheduler_proc = true;
    } else if (IsEnabled(
                   "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_SCHEDULER_PROC") &&
               selected != 0 && proc_context != selected &&
               IsReadableMemoryRange(proc_context + 0x60, sizeof(uintptr_t)) &&
               EnsureWritablePage(
                   reinterpret_cast<void*>(proc_context + 0x60))) {
      *reinterpret_cast<uintptr_t*>(proc_context + 0x60) = selected;
      current_proc = selected;
      forced_scheduler_proc = true;
    }
    static volatile sig_atomic_t resolver_scheduler_proc_logs = 0;
    if (resolver_scheduler_proc_logs < 16) {
      char msg[920];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver scheduler proc load off=0x%lx "
          "proc_context=%p current_proc=%p task=%p task_flags=%p "
          "selected=%p forced_scheduler_proc=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(proc_context),
          reinterpret_cast<void*>(current_proc), reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(task_flags),
          reinterpret_cast<void*>(selected), forced_scheduler_proc ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_scheduler_proc_logs;
    }
    ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(current_proc);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverSchedulerProcLoadOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverClosureDispatchOffset ||
      libroblox_offset == kStage6StartLuaResolverClosureDispatchOffset + 1) {
    const uintptr_t function_object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t callback = ReadPointerIfReadable(function_object + 0x00);
    const uintptr_t callback_arg =
        ReadPointerIfReadable(function_object + 0x08);
    static volatile sig_atomic_t resolver_dispatch_logs = 0;
    if (resolver_dispatch_logs < 16) {
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure dispatch off=0x%lx "
          "function_object=%p callback=%p callback_arg=%p "
          "arg_fields{%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(function_object),
          reinterpret_cast<void*>(callback),
          reinterpret_cast<void*>(callback_arg),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x20)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_dispatch_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(callback_arg);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverClosureDispatchOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverProcMatchBranchOffset ||
      libroblox_offset == kStage6StartLuaResolverProcMatchBranchOffset + 1) {
    const uintptr_t proc_context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t selected =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t current_proc = ReadPointerIfReadable(proc_context + 0x60);
    bool forced_proc_match = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_PROC_MATCH") &&
        selected != 0 && proc_context != selected &&
        IsReadableMemoryRange(proc_context + 0x60, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(proc_context + 0x60))) {
      *reinterpret_cast<uintptr_t*>(proc_context + 0x60) = selected;
      current_proc = selected;
      forced_proc_match = true;
    }
    const bool take_branch =
        selected != 0 && (current_proc == selected || proc_context == selected);
    static volatile sig_atomic_t resolver_proc_logs = 0;
    if (resolver_proc_logs < 16) {
      char msg[760];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [trace] Stage6 StartLua resolver proc match off=0x%lx "
                   "selected=%p proc_context=%p current_proc=%p "
                   "forced_proc_match=%d take_branch=%d\n",
                   static_cast<unsigned long>(libroblox_offset),
                   reinterpret_cast<void*>(selected),
                   reinterpret_cast<void*>(proc_context),
                   reinterpret_cast<void*>(current_proc),
                   forced_proc_match ? 1 : 0, take_branch ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_proc_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        (take_branch ? kStage6StartLuaResolverProcMatchTakenOffset
                     : kStage6StartLuaResolverProcMatchBranchOffset + 6));
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverCleanupProcExchangeOffset ||
      libroblox_offset ==
          kStage6StartLuaResolverCleanupProcExchangeOffset + 1) {
    uintptr_t current_proc =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t fallback_proc =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    bool forced_cleanup_proc = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_CLEANUP_PROC") &&
        current_proc < kStage5LowAddressThreshold &&
        fallback_proc >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(fallback_proc + 0x60, sizeof(uint32_t))) {
      current_proc = fallback_proc;
      ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(current_proc);
      forced_cleanup_proc = true;
    }
    if (current_proc < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(current_proc + 0x60, sizeof(uint32_t)) ||
        !EnsureWritablePage(reinterpret_cast<void*>(current_proc + 0x60))) {
      return false;
    }
    auto* state_slot = reinterpret_cast<uint32_t*>(current_proc + 0x60);
    const uint32_t old_state = *state_slot;
    const uint32_t new_state =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    *state_slot = new_state;
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(old_state);
    static volatile sig_atomic_t resolver_cleanup_logs = 0;
    if (resolver_cleanup_logs < 16) {
      char msg[720];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [trace] Stage6 StartLua resolver cleanup proc exchange "
                   "off=0x%lx current_proc=%p fallback_proc=%p old_state=0x%x "
                   "new_state=0x%x forced_cleanup_proc=%d\n",
                   static_cast<unsigned long>(libroblox_offset),
                   reinterpret_cast<void*>(current_proc),
                   reinterpret_cast<void*>(fallback_proc), old_state, new_state,
                   forced_cleanup_proc ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_cleanup_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverCleanupProcExchangeOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverScheduleReturnOffset ||
      libroblox_offset == kStage6StartLuaResolverScheduleReturnOffset + 1) {
    const uintptr_t schedule_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) &
        0xffffffffu;
    const uintptr_t task =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    static volatile sig_atomic_t resolver_schedule_logs = 0;
    if (resolver_schedule_logs < 16) {
      char msg[760];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver schedule return off=0x%lx "
          "schedule_result=0x%lx task=%p task_fields{28=%p 48=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          static_cast<unsigned long>(schedule_result),
          reinterpret_cast<void*>(task),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task + 0x48)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_schedule_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RBX] =
        static_cast<greg_t>(static_cast<uint32_t>(schedule_result));
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverScheduleReturnOffset + 2);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverClosureRunOffset ||
      libroblox_offset == kStage6StartLuaResolverClosureRunOffset + 1) {
    const uintptr_t closure =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t capture0 = ReadPointerIfReadable(closure + 0x00);
    const uintptr_t capture1 = ReadPointerIfReadable(closure + 0x08);
    const uintptr_t capture2 = ReadPointerIfReadable(closure + 0x10);
    const uintptr_t capture3 = ReadPointerIfReadable(closure + 0x18);
    const uintptr_t capture4 = ReadPointerIfReadable(closure + 0x20);
    static volatile sig_atomic_t resolver_closure_run_logs = 0;
    if (resolver_closure_run_logs < 16) {
      char msg[1180];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure run off=0x%lx "
          "closure=%p arg_rdi=%p arg_rsi=%p "
          "captures{%p,%p,%p,%p,%p} "
          "capture_values{%p,%p,%p,0x%x,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(closure),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI]),
          reinterpret_cast<void*>(capture0), reinterpret_cast<void*>(capture1),
          reinterpret_cast<void*>(capture2), reinterpret_cast<void*>(capture3),
          reinterpret_cast<void*>(capture4),
          reinterpret_cast<void*>(ReadPointerIfReadable(capture0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(capture1)),
          reinterpret_cast<void*>(ReadPointerIfReadable(capture2)),
          IsReadableMemoryRange(capture3, sizeof(uint8_t))
              ? *reinterpret_cast<const uint8_t*>(capture3)
              : 0xffu,
          reinterpret_cast<void*>(ReadPointerIfReadable(capture4)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_closure_run_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverClosureRunOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverClosureCoreOffset ||
      libroblox_offset == kStage6StartLuaResolverClosureCoreOffset + 1) {
    const uintptr_t proc_context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t size =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t task_arg =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    const uintptr_t mode =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    const uintptr_t queue = ReadPointerIfReadable(proc_context + 0x70);
    const uintptr_t current_proc = ReadPointerIfReadable(proc_context + 0x60);
    uintptr_t active_proc = ReadPointerIfReadable(proc_context + 0x68);
    const uintptr_t mode_task = mode & ~static_cast<uintptr_t>(0x1);
    const uintptr_t mode_task_flags = ReadPointerIfReadable(mode_task + 0x48);
    const uintptr_t selected_proc =
        mode_task_flags & ~static_cast<uintptr_t>(0x3);
    bool forced_active_proc = false;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_ACTIVE_PROC") &&
        active_proc == proc_context &&
        (current_proc != 0 || selected_proc != 0) &&
        IsReadableMemoryRange(proc_context + 0x68, sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(proc_context + 0x68))) {
      active_proc = current_proc != 0 ? current_proc : selected_proc;
      *reinterpret_cast<uintptr_t*>(proc_context + 0x68) = active_proc;
      forced_active_proc = true;
    }
    static volatile sig_atomic_t resolver_core_logs = 0;
    if (resolver_core_logs < 16) {
      char msg[2300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure core off=0x%lx "
          "proc_context=%p size=0x%lx task_arg=%p mode=%p "
          "proc_fields{60=%p 68=%p 70=%p} "
          "mode_task=%p mode_task_fields{28=%p 48=%p} selected_proc=%p "
          "forced_active_proc=%d "
          "queue_fields{0=%p 8=%p 10=%p 18=%p 28=%p 30=%p 650=%p} "
          "task_arg_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p "
          "30=%p 38=%p 40=%p 48=%p 68=%p 70=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(proc_context),
          static_cast<unsigned long>(size), reinterpret_cast<void*>(task_arg),
          reinterpret_cast<void*>(mode), reinterpret_cast<void*>(current_proc),
          reinterpret_cast<void*>(active_proc), reinterpret_cast<void*>(queue),
          reinterpret_cast<void*>(mode_task),
          reinterpret_cast<void*>(ReadPointerIfReadable(mode_task + 0x28)),
          reinterpret_cast<void*>(mode_task_flags),
          reinterpret_cast<void*>(selected_proc), forced_active_proc ? 1 : 0,
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(queue + 0x650)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x38)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x40)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x48)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(task_arg + 0x70)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_core_logs;
    }
    return emulate_push_rbp(kStage6StartLuaResolverClosureCoreOffset + 1);
  }

  if (libroblox_offset == kStage6StartLuaResolverClosureCoreAllocResultOffset ||
      libroblox_offset ==
          kStage6StartLuaResolverClosureCoreAllocResultOffset + 1) {
    const uintptr_t allocation_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    static volatile sig_atomic_t resolver_core_alloc_logs = 0;
    if (resolver_core_alloc_logs < 16) {
      char msg[520];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure core alloc result "
          "off=0x%lx allocation_result=%p branch_fallback=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(allocation_result),
          allocation_result == 0 ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_core_alloc_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + (allocation_result == 0 ? 0x2786865 : 0x27866ad));
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaResolverClosureCoreFallbackAllocResultOffset ||
      libroblox_offset ==
          kStage6StartLuaResolverClosureCoreFallbackAllocResultOffset + 1) {
    const uintptr_t allocation_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    static volatile sig_atomic_t resolver_core_fallback_alloc_logs = 0;
    if (resolver_core_fallback_alloc_logs < 16) {
      char msg[560];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure core fallback alloc "
          "result off=0x%lx allocation_result=%p branch_null_return=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(allocation_result),
          allocation_result == 0 ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_core_fallback_alloc_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + (allocation_result == 0 ? 0x27868bc : 0x2786877));
    return true;
  }

  if (libroblox_offset == kStage6StartLuaResolverClosureReturnOffset ||
      libroblox_offset == kStage6StartLuaResolverClosureReturnOffset + 1) {
    uintptr_t closure_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) &
        0xffffffffu;
    const bool forced_closure_success =
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_CLOSURE_SUCCESS") &&
        closure_result == 0;
    if (forced_closure_success) {
      closure_result = 1;
      ucontext->uc_mcontext.gregs[REG_RAX] =
          static_cast<greg_t>(closure_result);
    }
    const uintptr_t closure =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    static volatile sig_atomic_t resolver_closure_return_logs = 0;
    if (resolver_closure_return_logs < 16) {
      char msg[760];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua resolver closure return off=0x%lx "
          "closure=%p closure_result=0x%lx forced_closure_success=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(closure),
          static_cast<unsigned long>(closure_result),
          forced_closure_success ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++resolver_closure_return_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RCX] =
        static_cast<greg_t>(static_cast<uint32_t>(closure_result));
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaResolverClosureReturnOffset + 2);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaSharedRefcountReleaseHelperOffset ||
      libroblox_offset ==
          kStage6StartLuaSharedRefcountReleaseHelperOffset + 1) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    auto in_range = [](uintptr_t value, const unsigned char* base,
                       size_t size) -> bool {
      const uintptr_t begin = reinterpret_cast<uintptr_t>(base);
      return value >= begin && value < begin + size;
    };
    const char* scratch = "other";
    if (in_range(object, g_stage6_start_lua_callback_scratch,
                 sizeof(g_stage6_start_lua_callback_scratch))) {
      scratch = "callback";
    } else if (in_range(object, g_stage6_start_lua_anchor_scratch,
                        sizeof(g_stage6_start_lua_anchor_scratch))) {
      scratch = "anchor";
    } else if (in_range(object, g_stage6_start_lua_state_scratch,
                        sizeof(g_stage6_start_lua_state_scratch))) {
      scratch = "state";
    } else if (in_range(object, g_stage6_start_lua_target_table_scratch,
                        sizeof(g_stage6_start_lua_target_table_scratch))) {
      scratch = "target-table";
    } else if (in_range(object, g_stage6_start_lua_refcount_scratch,
                        sizeof(g_stage6_start_lua_refcount_scratch))) {
      scratch = "refcount";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_object_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_object_scratch))) {
      scratch = "system-dialog-object";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_list_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_list_scratch))) {
      scratch = "system-dialog-list";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_item_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_item_scratch))) {
      scratch = "system-dialog-item";
    } else if (in_range(object, g_stage5_fallback_region,
                        sizeof(g_stage5_fallback_region))) {
      scratch = "stage5-fallback";
    }

    const uintptr_t field0 = ReadPointerIfReadable(object + 0x00);
    const uintptr_t field8 = ReadPointerIfReadable(object + 0x08);
    const uint32_t field10 =
        IsReadableMemoryRange(object + 0x10, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x10)
            : 0xffffffffu;
    const uint32_t field14 =
        IsReadableMemoryRange(object + 0x14, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x14)
            : 0xffffffffu;
    const uintptr_t field18 = ReadPointerIfReadable(object + 0x18);
    const uintptr_t field20 = ReadPointerIfReadable(object + 0x20);
    static volatile sig_atomic_t shared_release_logs = 0;
    if (shared_release_logs < 64) {
      char msg[900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua shared refcount release object=%p "
          "scratch=%s fields{0=%p 8=%p 10=0x%x 14=0x%x 18=%p 20=%p} "
          "masked=0x%x\n",
          reinterpret_cast<void*>(object), scratch,
          reinterpret_cast<void*>(field0), reinterpret_cast<void*>(field8),
          field10, field14, reinterpret_cast<void*>(field18),
          reinterpret_cast<void*>(field20), field10 & field14);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++shared_release_logs;
    }

    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp - sizeof(uintptr_t));
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaSharedRefcountReleaseHelperOffset +
          1);
      return true;
    }
    return false;
  }

  if (libroblox_offset == kStage6StartLuaRefcountReleaseHelperOffset ||
      libroblox_offset == kStage6StartLuaRefcountReleaseHelperOffset + 1) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    auto in_range = [](uintptr_t value, const unsigned char* base,
                       size_t size) -> bool {
      const uintptr_t begin = reinterpret_cast<uintptr_t>(base);
      return value >= begin && value < begin + size;
    };
    const char* scratch = "other";
    if (in_range(object, g_stage6_start_lua_callback_scratch,
                 sizeof(g_stage6_start_lua_callback_scratch))) {
      scratch = "callback";
    } else if (in_range(object, g_stage6_start_lua_anchor_scratch,
                        sizeof(g_stage6_start_lua_anchor_scratch))) {
      scratch = "anchor";
    } else if (in_range(object, g_stage6_start_lua_state_scratch,
                        sizeof(g_stage6_start_lua_state_scratch))) {
      scratch = "state";
    } else if (in_range(object, g_stage6_start_lua_target_table_scratch,
                        sizeof(g_stage6_start_lua_target_table_scratch))) {
      scratch = "target-table";
    } else if (in_range(object, g_stage6_start_lua_refcount_scratch,
                        sizeof(g_stage6_start_lua_refcount_scratch))) {
      scratch = "refcount";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_object_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_object_scratch))) {
      scratch = "system-dialog-object";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_list_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_list_scratch))) {
      scratch = "system-dialog-list";
    } else if (in_range(
                   object, g_stage6_start_lua_system_dialog_item_scratch,
                   sizeof(g_stage6_start_lua_system_dialog_item_scratch))) {
      scratch = "system-dialog-item";
    } else if (in_range(object, g_stage5_fallback_region,
                        sizeof(g_stage5_fallback_region))) {
      scratch = "stage5-fallback";
    }

    const uintptr_t field0 = ReadPointerIfReadable(object + 0x00);
    const uintptr_t field8 = ReadPointerIfReadable(object + 0x08);
    const uintptr_t field10 = ReadPointerIfReadable(object + 0x10);
    const uintptr_t field20 = ReadPointerIfReadable(object + 0x20);
    const uint64_t masked_count =
        static_cast<uint64_t>(field20) & 0x3fffffffffffffffull;
    bool seeded = false;
    if (masked_count == 0 &&
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_REFCOUNT_RELEASE_ZERO") &&
        std::strcmp(scratch, "other") != 0 &&
        IsReadableMemoryRange(object + 0x20, sizeof(uint64_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(object + 0x20))) {
      *reinterpret_cast<uint64_t*>(object + 0x20) =
          kStage6FakeIntrusiveRefcount;
      seeded = true;
    }

    static volatile sig_atomic_t release_logs = 0;
    if (release_logs < 64) {
      char msg[900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua refcount release object=%p "
          "scratch=%s fields{0=%p 8=%p 10=%p 20=0x%lx masked=0x%llx} "
          "seeded=%d\n",
          reinterpret_cast<void*>(object), scratch,
          reinterpret_cast<void*>(field0), reinterpret_cast<void*>(field8),
          reinterpret_cast<void*>(field10), static_cast<unsigned long>(field20),
          static_cast<unsigned long long>(masked_count), seeded ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++release_logs;
    }

    const uintptr_t rsp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp - sizeof(uintptr_t));
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaRefcountReleaseHelperOffset + 1);
      return true;
    }
    return false;
  }

  if (libroblox_offset == kStage6AsyncAppBridgeHashAllocationStoreOffset ||
      libroblox_offset == kStage6AsyncAppBridgeHashAllocationStoreOffset + 1) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t allocation =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    const uintptr_t requested_bytes =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R8]);
    bool used_fallback = false;
    if (allocation == 0 &&
        !IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_HASH_ALLOC_FALLBACK")) {
      const size_t clear_size =
          requested_bytes > 0 &&
                  requested_bytes < kStage6AppBridgeHashScratchSize
              ? static_cast<size_t>(requested_bytes)
              : kStage6AppBridgeHashScratchSize;
      std::memset(g_stage6_app_bridge_hash_scratch, 0, clear_size);
      allocation =
          reinterpret_cast<uintptr_t>(g_stage6_app_bridge_hash_scratch);
      ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(allocation);
      used_fallback = true;
    }

    bool stored = false;
    if (object >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(object + 0x08, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(object + 0x08) = allocation;
      stored = true;
    }

    char msg[780];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 AppBridge hash allocation store "
        "off=0x%lx object=%p allocation=%p requested=0x%lx "
        "fallback=%d stored=%d fields{0=%p 4=0x%x 8=%p 10=%p 18=0x%x "
        "1c=0x%x 20=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(object), reinterpret_cast<void*>(allocation),
        static_cast<unsigned long>(requested_bytes), used_fallback ? 1 : 0,
        stored ? 1 : 0,
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x00)),
        IsReadableMemoryRange(object + 0x04, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x04)
            : 0xffffffffu,
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x10)),
        IsReadableMemoryRange(object + 0x18, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x18)
            : 0xffffffffu,
        IsReadableMemoryRange(object + 0x1c, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x1c)
            : 0xffffffffu,
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6AsyncAppBridgeHashAllocationStoreOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6AppBridgeVectorAllocationNullCheckOffset ||
      libroblox_offset == kStage6AppBridgeVectorAllocationNullCheckOffset + 1) {
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t allocation =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t requested_bytes = ReadPointerIfReadable(rbp - 0x60);
    const uintptr_t requested_alignment = ReadPointerIfReadable(rbp - 0x58);
    bool used_fallback = false;
    if (allocation == 0 &&
        !IsDisabled("MOCKTAIL_PATCH_STAGE6_APP_BRIDGE_VECTOR_ALLOC_FALLBACK")) {
      const size_t clear_size =
          requested_bytes > 0 &&
                  requested_bytes < kStage6AppBridgeHashScratchSize
              ? static_cast<size_t>(requested_bytes)
              : kStage6AppBridgeHashScratchSize;
      std::memset(g_stage6_app_bridge_vector_scratch, 0, clear_size);
      allocation =
          reinterpret_cast<uintptr_t>(g_stage6_app_bridge_vector_scratch);
      ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(allocation);
      used_fallback = true;
    }

    bool stored = false;
    if (object >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(object + 0x08, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(object + 0x08) = allocation;
      stored = true;
    }
    if (rbp >= 0x38 && IsReadableMemoryRange(rbp - 0x38, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(rbp - 0x38) = allocation;
    }

    char msg[860];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 AppBridge vector allocation check "
        "off=0x%lx object=%p allocation=%p requested=0x%lx align=0x%lx "
        "fallback=%d stored=%d fields{0=0x%x 4=0x%x 8=%p 18=0x%x "
        "1c=0x%x 20=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(object), reinterpret_cast<void*>(allocation),
        static_cast<unsigned long>(requested_bytes),
        static_cast<unsigned long>(requested_alignment), used_fallback ? 1 : 0,
        stored ? 1 : 0,
        IsReadableMemoryRange(object + 0x00, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x00)
            : 0xffffffffu,
        IsReadableMemoryRange(object + 0x04, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x04)
            : 0xffffffffu,
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x08)),
        IsReadableMemoryRange(object + 0x18, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x18)
            : 0xffffffffu,
        IsReadableMemoryRange(object + 0x1c, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(object + 0x1c)
            : 0xffffffffu,
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6AppBridgeVectorAllocationNullCheckOffset + 9);
    return true;
  }

  if (libroblox_offset == kStage6RbxmFileManagerEntryProbeOffset ||
      libroblox_offset == kStage6RbxmFileManagerEntryProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t output_arg = static_cast<uintptr_t>(gregs[REG_RDI]);
    const uintptr_t input_arg = static_cast<uintptr_t>(gregs[REG_RSI]);
    static volatile sig_atomic_t rbxm_entry_logs = 0;
    if (rbxm_entry_logs < 32) {
      char input_preview[160];
      char input_hex[180];
      char cache_registry_preview[420];
      ReadLibcxxStringPreview(input_arg, input_preview, sizeof(input_preview));
      ReadMemoryHexPreview(input_arg, input_hex, sizeof(input_hex));
      ReadRbxmFileManagerCacheRegistryPreview(libroblox_base,
                                              cache_registry_preview,
                                              sizeof(cache_registry_preview));
      char msg[1320];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 RbxmFileManager status entry "
          "off=0x%lx output=%p input=%p input_string=\"%s\" "
          "input_preview=\"%s\" %s\n",
          static_cast<unsigned long>(kStage6RbxmFileManagerEntryProbeOffset),
          reinterpret_cast<void*>(output_arg),
          reinterpret_cast<void*>(input_arg), input_preview, input_hex,
          cache_registry_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_entry_logs;
    }

    gregs[REG_R14] = static_cast<greg_t>(input_arg);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmFileManagerEntryProbeOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6RbxmFileManagerPostCheckStatusProbeOffset ||
      libroblox_offset ==
          kStage6RbxmFileManagerPostCheckStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t state = static_cast<uintptr_t>(gregs[REG_R15]);
    const uintptr_t status_slot = state + 0x60;
    const uint32_t status =
        IsReadableMemoryRange(status_slot, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(status_slot)
            : 0xffffffffu;
    const uintptr_t next_offset = status == 2 ? 0x5fa78f2 : 0x5fa7919;
    static volatile sig_atomic_t rbxm_post_check_logs = 0;
    if (rbxm_post_check_logs < 32) {
      char state_preview[180];
      char path_preview[160];
      char cache_registry_preview[420];
      ReadMemoryHexPreview(state, state_preview, sizeof(state_preview));
      ReadLibcxxStringPreview(state, path_preview, sizeof(path_preview));
      ReadRbxmFileManagerCacheRegistryPreview(libroblox_base,
                                              cache_registry_preview,
                                              sizeof(cache_registry_preview));
      char msg[1400];
      int len = snprintf(msg, sizeof(msg),
                         "  [trace] Stage6 RbxmFileManager status post-check "
                         "off=0x%lx state=%p status=0x%x path=\"%s\" "
                         "state_preview=\"%s\" next=0x%lx %s\n",
                         static_cast<unsigned long>(
                             kStage6RbxmFileManagerPostCheckStatusProbeOffset),
                         reinterpret_cast<void*>(state), status, path_preview,
                         state_preview, static_cast<unsigned long>(next_offset),
                         cache_registry_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_post_check_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset ==
          kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset ||
      libroblox_offset ==
          kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset + 1 ||
      libroblox_offset == kStage6RbxmFileManagerCachingDisabledProbeOffset ||
      libroblox_offset ==
          kStage6RbxmFileManagerCachingDisabledProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t input_arg = static_cast<uintptr_t>(gregs[REG_RBX]);
    const uintptr_t state = static_cast<uintptr_t>(gregs[REG_R14]);
    const bool local_storage_unavailable =
        libroblox_offset ==
            kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset ||
        libroblox_offset ==
            kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset + 1;
    const char* reason = local_storage_unavailable ? "local-storage-unavailable"
                                                   : "caching-disabled";
    const uintptr_t reason_offset =
        local_storage_unavailable
            ? kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset
            : kStage6RbxmFileManagerCachingDisabledProbeOffset;
    static volatile sig_atomic_t rbxm_reason_logs = 0;
    if (rbxm_reason_logs < 32) {
      char input_preview[160];
      char state_preview[180];
      char cache_registry_preview[420];
      ReadLibcxxStringPreview(input_arg, input_preview, sizeof(input_preview));
      ReadMemoryHexPreview(state, state_preview, sizeof(state_preview));
      ReadRbxmFileManagerCacheRegistryPreview(libroblox_base,
                                              cache_registry_preview,
                                              sizeof(cache_registry_preview));
      char msg[1440];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 RbxmFileManager status %s "
          "off=0x%lx rbp=%p state=%p input=%p input_string=\"%s\" "
          "state_preview=\"%s\" next=0x%lx %s\n",
          reason, static_cast<unsigned long>(reason_offset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(state),
          reinterpret_cast<void*>(input_arg), input_preview, state_preview,
          static_cast<unsigned long>(
              kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset),
          cache_registry_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_reason_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset);
    return true;
  }

  if (libroblox_offset ==
          kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset ||
      libroblox_offset ==
          kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t state = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t input_arg = static_cast<uintptr_t>(gregs[REG_RBX]);
    const uintptr_t status_slot = state + 0x60;
    bool stored = false;
    if (IsReadableMemoryRange(status_slot, sizeof(uint32_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(status_slot))) {
      *reinterpret_cast<uint32_t*>(status_slot) = 0;
      stored = true;
    }
    static volatile sig_atomic_t rbxm_zero_logs = 0;
    if (rbxm_zero_logs < 32) {
      char input_preview[160];
      char state_preview[180];
      ReadLibcxxStringPreview(input_arg, input_preview, sizeof(input_preview));
      ReadMemoryHexPreview(state, state_preview, sizeof(state_preview));
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 RbxmFileManager status no-local-storage-zero "
          "off=0x%lx state=%p input=%p input_string=\"%s\" "
          "stored=%d state_preview=\"%s\"\n",
          static_cast<unsigned long>(
              kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset),
          reinterpret_cast<void*>(state), reinterpret_cast<void*>(input_arg),
          input_preview, stored ? 1 : 0, state_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_zero_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset +
        8);
    return true;
  }

  if (libroblox_offset == kStage6RbxmFileManagerPendingStatusProbeOffset ||
      libroblox_offset == kStage6RbxmFileManagerPendingStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t state = static_cast<uintptr_t>(gregs[REG_RBX]);
    const uintptr_t status_slot = state + 0x60;
    bool stored = false;
    if (IsReadableMemoryRange(status_slot, sizeof(uint32_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(status_slot))) {
      *reinterpret_cast<uint32_t*>(status_slot) = 1;
      stored = true;
    }
    static volatile sig_atomic_t rbxm_pending_logs = 0;
    if (rbxm_pending_logs < 32) {
      char state_preview[180];
      char slot00[160];
      char slot18[160];
      char slot30[160];
      char slot48[160];
      ReadMemoryHexPreview(state, state_preview, sizeof(state_preview));
      ReadLibcxxStringPreview(state + 0x00, slot00, sizeof(slot00));
      ReadLibcxxStringPreview(state + 0x18, slot18, sizeof(slot18));
      ReadLibcxxStringPreview(state + 0x30, slot30, sizeof(slot30));
      ReadLibcxxStringPreview(state + 0x48, slot48, sizeof(slot48));
      char msg[1280];
      int len = snprintf(msg, sizeof(msg),
                         "  [trace] Stage6 RbxmFileManager status pending-one "
                         "off=0x%lx state=%p stored=%d "
                         "strings{00=\"%s\" 18=\"%s\" 30=\"%s\" 48=\"%s\"} "
                         "state_preview=\"%s\"\n",
                         static_cast<unsigned long>(
                             kStage6RbxmFileManagerPendingStatusProbeOffset),
                         reinterpret_cast<void*>(state), stored ? 1 : 0, slot00,
                         slot18, slot30, slot48, state_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_pending_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmFileManagerPendingStatusProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6RbxmFileManagerSuccessStatusProbeOffset ||
      libroblox_offset == kStage6RbxmFileManagerSuccessStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t state = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t status_slot = state + 0x60;
    bool stored = false;
    if (IsReadableMemoryRange(status_slot, sizeof(uint32_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(status_slot))) {
      *reinterpret_cast<uint32_t*>(status_slot) = 2;
      stored = true;
    }
    static volatile sig_atomic_t rbxm_success_logs = 0;
    if (rbxm_success_logs < 32) {
      char path_preview[160];
      char state_preview[180];
      ReadLibcxxStringPreview(state, path_preview, sizeof(path_preview));
      ReadMemoryHexPreview(state, state_preview, sizeof(state_preview));
      char msg[900];
      int len = snprintf(msg, sizeof(msg),
                         "  [trace] Stage6 RbxmFileManager status success-two "
                         "off=0x%lx state=%p path=\"%s\" stored=%d "
                         "state_preview=\"%s\"\n",
                         static_cast<unsigned long>(
                             kStage6RbxmFileManagerSuccessStatusProbeOffset),
                         reinterpret_cast<void*>(state), path_preview,
                         stored ? 1 : 0, state_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_success_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmFileManagerSuccessStatusProbeOffset + 8);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchInnerLoaderStatusProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchInnerLoaderStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uint32_t status =
        static_cast<uint32_t>(static_cast<uintptr_t>(gregs[REG_RBX]));
    const uintptr_t out_arg = ReadPointerIfReadable(rbp - 0x108);
    static volatile sig_atomic_t inner_status_logs = 0;
    if (inner_status_logs < 16) {
      char msg[1700];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step inner-status "
          "off=0x%lx rbp=%p status=0x%x out_arg=%p out_pair=%p "
          "out_ref=%p slots{f0=%p e8=%p e0=%p d8=%p d0=%p c8=%p "
          "a0=%p 98=%p 88=%p 60=%p 58=%p} next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchInnerLoaderStatusProbeOffset),
          reinterpret_cast<void*>(rbp), status,
          reinterpret_cast<void*>(out_arg),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xf0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xd8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xd0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xc8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x88)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)),
          static_cast<unsigned long>(status == 1 ? 0x2418e8f : 0x241902e));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++inner_status_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        status == 1 ? libroblox_base + 0x2418e8f : libroblox_base + 0x241902e);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchInnerLoaderReturnProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchInnerLoaderReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t out_arg = ReadPointerIfReadable(rbp - 0x108);
    static volatile sig_atomic_t inner_return_logs = 0;
    if (inner_return_logs < 16) {
      char msg[1500];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step inner-return "
          "off=0x%lx rbp=%p out_arg=%p out_pair=%p out_ref=%p "
          "result_slots{f0=%p e8=%p e0=%p d8=%p d0=%p c8=%p "
          "60=%p 58=%p}\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchInnerLoaderReturnProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(out_arg),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xf0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xd8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xd0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xc8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++inner_return_logs;
    }

    gregs[REG_RAX] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x108));
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchInnerLoaderReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6DataModelPatchBuildListEmptyBranchProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildListEmptyBranchProbeOffset + 1 ||
      libroblox_offset ==
          kStage6DataModelPatchBuildContentNullBranchProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildContentNullBranchProbeOffset + 1 ||
      libroblox_offset ==
          kStage6DataModelPatchBuildContentEmptyBranchProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildContentEmptyBranchProbeOffset + 1 ||
      libroblox_offset ==
          kStage6DataModelPatchBuildFeatureGateBranchProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildFeatureGateBranchProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t rax = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t rcx = static_cast<uintptr_t>(gregs[REG_RCX]);
    const uintptr_t r15 = static_cast<uintptr_t>(gregs[REG_R15]);
    const bool take_branch = (gregs[REG_EFL] & 0x40) != 0;
    uintptr_t probe_offset =
        kStage6DataModelPatchBuildListEmptyBranchProbeOffset;
    uintptr_t taken_offset = 0x5f9fa28;
    uintptr_t fallthrough_offset = 0x5f9f808;
    const char* branch_name = "build-list-empty";
    if (libroblox_offset ==
            kStage6DataModelPatchBuildContentNullBranchProbeOffset ||
        libroblox_offset ==
            kStage6DataModelPatchBuildContentNullBranchProbeOffset + 1) {
      probe_offset = kStage6DataModelPatchBuildContentNullBranchProbeOffset;
      fallthrough_offset = 0x5f9f818;
      branch_name = "build-content-null";
    } else if (libroblox_offset ==
                   kStage6DataModelPatchBuildContentEmptyBranchProbeOffset ||
               libroblox_offset ==
                   kStage6DataModelPatchBuildContentEmptyBranchProbeOffset +
                       1) {
      probe_offset = kStage6DataModelPatchBuildContentEmptyBranchProbeOffset;
      fallthrough_offset = 0x5f9f825;
      branch_name = "build-content-empty";
    } else if (libroblox_offset ==
                   kStage6DataModelPatchBuildFeatureGateBranchProbeOffset ||
               libroblox_offset ==
                   kStage6DataModelPatchBuildFeatureGateBranchProbeOffset + 1) {
      probe_offset = kStage6DataModelPatchBuildFeatureGateBranchProbeOffset;
      taken_offset = 0x5f9fa7e;
      fallthrough_offset = 0x5f9f879;
      branch_name = "build-feature-gate";
    }

    const uintptr_t parent_input = ReadPointerIfReadable(rbp - 0xf8);
    static volatile sig_atomic_t build_branch_logs = 0;
    if (build_branch_logs < 16) {
      char msg[1900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step %s "
          "off=0x%lx rbp=%p zf=%d take_branch=%d rax=%p rcx=%p "
          "r15=%p al=0x%lx list_holder=%p list_begin=%p list_end=%p "
          "rax0=%p rax8=%p rcx0=%p rcx8=%p parent_input=%p "
          "parent_pair=%p parent_ref=%p out_arg=%p next=0x%lx\n",
          branch_name, static_cast<unsigned long>(probe_offset),
          reinterpret_cast<void*>(rbp), take_branch ? 1 : 0,
          take_branch ? 1 : 0, reinterpret_cast<void*>(rax),
          reinterpret_cast<void*>(rcx), reinterpret_cast<void*>(r15),
          static_cast<unsigned long>(rax & 0xff),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x58))),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x58) + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rax)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rax + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rcx)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x08)),
          reinterpret_cast<void*>(parent_input),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input)),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x110)),
          static_cast<unsigned long>(take_branch ? taken_offset
                                                 : fallthrough_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++build_branch_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + (take_branch ? taken_offset : fallthrough_offset));
    return true;
  }

  if (libroblox_offset ==
          kStage6DataModelPatchBuildDeserializeReturnProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildDeserializeReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t call_result = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t list_holder = ReadPointerIfReadable(rbp - 0x58);
    const uintptr_t parent_input = ReadPointerIfReadable(rbp - 0xf8);
    const uintptr_t parent_pair = ReadPointerIfReadable(parent_input);
    const uintptr_t parent_ref = ReadPointerIfReadable(parent_input + 0x08);
    const uintptr_t prepared_input0 = ReadPointerIfReadable(parent_pair);
    const uintptr_t prepared_input8 = ReadPointerIfReadable(parent_pair + 0x08);
    const uintptr_t prepared_input10 =
        ReadPointerIfReadable(parent_pair + 0x10);
    const uintptr_t prepared_input18 =
        ReadPointerIfReadable(parent_pair + 0x18);
    static volatile sig_atomic_t build_deserialize_return_logs = 0;
    if (build_deserialize_return_logs < 16) {
      char parent_pair_preview[180];
      char parent_ref_preview[180];
      char prepared_input0_preview[180];
      char prepared_input8_preview[180];
      char prepared_input10_preview[180];
      char prepared_input18_preview[180];
      ReadMemoryHexPreview(parent_pair, parent_pair_preview,
                           sizeof(parent_pair_preview));
      ReadMemoryHexPreview(parent_ref, parent_ref_preview,
                           sizeof(parent_ref_preview));
      ReadMemoryHexPreview(prepared_input0, prepared_input0_preview,
                           sizeof(prepared_input0_preview));
      ReadMemoryHexPreview(prepared_input8, prepared_input8_preview,
                           sizeof(prepared_input8_preview));
      ReadMemoryHexPreview(prepared_input10, prepared_input10_preview,
                           sizeof(prepared_input10_preview));
      ReadMemoryHexPreview(prepared_input18, prepared_input18_preview,
                           sizeof(prepared_input18_preview));
      char msg[4200];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "build-deserialize-return off=0x%lx rbp=%p call_result=%p "
          "list_holder=%p list_begin=%p list_end=%p list_cap=%p "
          "parent_input=%p parent_pair=%p parent_ref=%p "
          "parent_pair_preview=\"%s\" parent_ref_preview=\"%s\" "
          "prepared_input0=%p prepared_input8=%p prepared_input10=%p "
          "prepared_input18=%p prepared_input0_preview=\"%s\" "
          "prepared_input8_preview=\"%s\" prepared_input10_preview=\"%s\" "
          "prepared_input18_preview=\"%s\" "
          "scratch{80=%p 78=%p 70=%p 68=%p 60=%p 58=%p} "
          "regs{r12=%p r13=%p r14=%p r15=%p}\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchBuildDeserializeReturnProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(call_result),
          reinterpret_cast<void*>(list_holder),
          reinterpret_cast<void*>(ReadPointerIfReadable(list_holder)),
          reinterpret_cast<void*>(ReadPointerIfReadable(list_holder + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(list_holder + 0x10)),
          reinterpret_cast<void*>(parent_input),
          reinterpret_cast<void*>(parent_pair),
          reinterpret_cast<void*>(parent_ref), parent_pair_preview,
          parent_ref_preview, reinterpret_cast<void*>(prepared_input0),
          reinterpret_cast<void*>(prepared_input8),
          reinterpret_cast<void*>(prepared_input10),
          reinterpret_cast<void*>(prepared_input18), prepared_input0_preview,
          prepared_input8_preview, prepared_input10_preview,
          prepared_input18_preview,
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x80)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x78)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x60)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)),
          reinterpret_cast<void*>(static_cast<uintptr_t>(gregs[REG_R12])),
          reinterpret_cast<void*>(static_cast<uintptr_t>(gregs[REG_R13])),
          reinterpret_cast<void*>(static_cast<uintptr_t>(gregs[REG_R14])),
          reinterpret_cast<void*>(static_cast<uintptr_t>(gregs[REG_R15])));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++build_deserialize_return_logs;
    }

    gregs[REG_RAX] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x108));
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6DataModelPatchBuildDeserializeReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6RbxmInstIdsReturnProbeOffset ||
      libroblox_offset == kStage6RbxmInstIdsReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t error_object = static_cast<uintptr_t>(gregs[REG_R15]);
    const unsigned int error_flag =
        IsReadableMemoryRange(error_object + 0x20, 1)
            ? *reinterpret_cast<const unsigned char*>(error_object + 0x20)
            : 0xffu;
    const uintptr_t ids_begin = ReadPointerIfReadable(rbp - 0x50);
    const uintptr_t ids_end = ReadPointerIfReadable(rbp - 0x48);
    const uintptr_t ids_cap = ReadPointerIfReadable(rbp - 0x40);
    char chunk_tag[5] = {'\0', '\0', '\0', '\0', '\0'};
    if (IsReadableMemoryRange(rbp - 0xe0, 4)) {
      const auto* raw_tag = reinterpret_cast<const unsigned char*>(rbp - 0xe0);
      for (size_t i = 0; i < 4; ++i) {
        chunk_tag[i] = (raw_tag[i] >= 0x20 && raw_tag[i] <= 0x7e)
                           ? static_cast<char>(raw_tag[i])
                           : '.';
      }
    }

    static volatile sig_atomic_t rbxm_prnt_ids_logs = 0;
    if (rbxm_prnt_ids_logs < 16) {
      char msg[2100];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "inst-ids-return off=0x%lx rbp=%p error=%p error_flag=0x%x "
          "size_arg=0x%x chunk{index=%u tag=\"%s\"} "
          "ids{begin=%p end=%p cap=%p count=%llu first=%d second=%d "
          "third=%d} stream{0=%p 8=%p 10=%p 18=%p 20=%p} next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmInstIdsReturnProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(error_object),
          error_flag, ReadU32IfReadable(rbp - 0x308),
          ReadU32IfReadable(rbp - 0x438), chunk_tag,
          reinterpret_cast<void*>(ids_begin), reinterpret_cast<void*>(ids_end),
          reinterpret_cast<void*>(ids_cap),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x04)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x430)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x428)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x420)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x418)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x410)),
          static_cast<unsigned long>(error_flag == 0 ? 0x2dea23c : 0x2dea134));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prnt_ids_logs;
    }

    const uintptr_t next_offset = error_flag == 0 ? 0x2dea23c : 0x2dea134;
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmInstModeBranchProbeOffset ||
      libroblox_offset == kStage6RbxmInstModeBranchProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const unsigned int mode = static_cast<unsigned int>(
        static_cast<uintptr_t>(gregs[REG_RAX]) & 0xffu);
    const uintptr_t ids_begin = ReadPointerIfReadable(rbp - 0x50);
    const uintptr_t ids_end = ReadPointerIfReadable(rbp - 0x48);
    const uintptr_t ids_cap = ReadPointerIfReadable(rbp - 0x40);
    const uintptr_t class_entries_begin = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t class_entries_end = ReadPointerIfReadable(rbp - 0x3f0);
    const unsigned int saved_mode =
        IsReadableMemoryRange(rbp - 0x441, 1)
            ? *reinterpret_cast<const unsigned char*>(rbp - 0x441)
            : 0xffu;
    const uintptr_t next_offset = mode == 1u ? 0x2dea26c : 0x2dea302;

    static volatile sig_atomic_t rbxm_inst_mode_branch_logs = 0;
    if (rbxm_inst_mode_branch_logs < 16) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "inst-mode-branch off=0x%lx rbp=%p mode=0x%x saved_mode=0x%x "
          "ids{begin=%p end=%p cap=%p count=%llu first=%d second=%d "
          "third=%d} class_entries{begin=%p end=%p count=%llu} "
          "vectors{360x8=%llu 380x10=%llu} saved_error=%p next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmInstModeBranchProbeOffset),
          reinterpret_cast<void*>(rbp), mode, saved_mode,
          reinterpret_cast<void*>(ids_begin), reinterpret_cast<void*>(ids_end),
          reinterpret_cast<void*>(ids_cap),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x04)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x08)),
          reinterpret_cast<void*>(class_entries_begin),
          reinterpret_cast<void*>(class_entries_end),
          ReadVectorElementCountIfReadable(rbp - 0x3f8, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x360, 0x08),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x450)),
          static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_inst_mode_branch_logs;
    }

    if (IsReadableMemoryRange(rbp - 0x450, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(rbp - 0x450) =
          static_cast<uintptr_t>(gregs[REG_R14]);
    }
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmInstProviderReturnProbeOffset ||
      libroblox_offset == kStage6RbxmInstProviderReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t provider = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t factory_token = ReadPointerIfReadable(rbp - 0x4b8);
    char class_name[160];
    char token_preview[180];
    char provider_preview[180];
    ReadLibcxxStringPreview(rbp - 0x300, class_name, sizeof(class_name));
    ReadMemoryHexPreview(factory_token, token_preview, sizeof(token_preview));
    ReadMemoryHexPreview(provider, provider_preview, sizeof(provider_preview));

    static volatile sig_atomic_t rbxm_inst_provider_return_logs = 0;
    if (rbxm_inst_provider_return_logs < 16 || provider != 0) {
      char msg[1700];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "inst-provider-return off=0x%lx rbp=%p class_name=\"%s\" "
          "factory_token=%p provider=%p provider_vtable=%p "
          "token_preview=\"%s\" provider_preview=\"%s\" next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmInstProviderReturnProbeOffset),
          reinterpret_cast<void*>(rbp), class_name,
          reinterpret_cast<void*>(factory_token),
          reinterpret_cast<void*>(provider),
          reinterpret_cast<void*>(ReadPointerIfReadable(provider)),
          token_preview, provider_preview,
          static_cast<unsigned long>(kStage6RbxmInstProviderReturnProbeOffset +
                                     7));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_inst_provider_return_logs;
    }

    if (IsReadableMemoryRange(rbp - 0x478, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(rbp - 0x478) = provider;
    }
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmInstProviderReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6RbxmInstFactoryResultProbeOffset ||
      libroblox_offset == kStage6RbxmInstFactoryResultProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t loop_index = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t ids_begin = ReadPointerIfReadable(rbp - 0x50);
    const uint32_t instance_id =
        ReadU32IfReadable(ids_begin + loop_index * sizeof(uint32_t));
    const uintptr_t object_pair = ReadPointerIfReadable(rbp - 0x330);
    const uintptr_t object_ref = ReadPointerIfReadable(rbp - 0x328);
    const uintptr_t next_offset = object_pair == 0 ? 0x2dea5b1 : 0x2dea576;

    char class_name[160];
    ReadLibcxxStringPreview(rbp - 0x300, class_name, sizeof(class_name));
    static volatile sig_atomic_t rbxm_inst_factory_result_logs = 0;
    if (rbxm_inst_factory_result_logs < 96 ||
        (object_pair != 0 && rbxm_inst_factory_result_logs < 160)) {
      char msg[1900];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "inst-factory-result off=0x%lx rbp=%p index=%llu id=%d "
          "class_name=\"%s\" object_pair=%p object_ref=%p "
          "provider=%p factory_input=%p factory_token=%p "
          "table_count=%llu ids_count=%llu next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmInstFactoryResultProbeOffset),
          reinterpret_cast<void*>(rbp),
          static_cast<unsigned long long>(loop_index),
          static_cast<int32_t>(instance_id), class_name,
          reinterpret_cast<void*>(object_pair),
          reinterpret_cast<void*>(object_ref),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x478)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x4c0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x4b8)),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04),
          static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_inst_factory_result_logs;
    }

    gregs[REG_RAX] = static_cast<greg_t>(object_pair);
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmInstTableInsertReturnProbeOffset ||
      libroblox_offset == kStage6RbxmInstTableInsertReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t loop_index = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t ids_begin = ReadPointerIfReadable(rbp - 0x50);
    const uint32_t instance_id =
        ReadU32IfReadable(ids_begin + loop_index * sizeof(uint32_t));
    const uintptr_t object_table = ReadPointerIfReadable(rbp - 0x380);
    const uintptr_t object_slot =
        object_table + static_cast<uintptr_t>(instance_id) * 0x10;
    const uintptr_t object_pair = ReadPointerIfReadable(rbp - 0x330);
    const uintptr_t object_ref = ReadPointerIfReadable(rbp - 0x328);

    static volatile sig_atomic_t rbxm_inst_table_insert_logs = 0;
    if (rbxm_inst_table_insert_logs < 96 ||
        (ReadPointerIfReadable(object_slot) != 0 &&
         rbxm_inst_table_insert_logs < 160)) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "inst-table-insert-return off=0x%lx rbp=%p index=%llu id=%d "
          "source_pair=%p source_ref=%p table_slot=%p slot_pair=%p "
          "slot_ref=%p table_count=%llu next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6RbxmInstTableInsertReturnProbeOffset),
          reinterpret_cast<void*>(rbp),
          static_cast<unsigned long long>(loop_index),
          static_cast<int32_t>(instance_id),
          reinterpret_cast<void*>(object_pair),
          reinterpret_cast<void*>(object_ref),
          reinterpret_cast<void*>(object_slot),
          reinterpret_cast<void*>(ReadPointerIfReadable(object_slot)),
          reinterpret_cast<void*>(ReadPointerIfReadable(object_slot + 0x08)),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          static_cast<unsigned long>(
              kStage6RbxmInstTableInsertReturnProbeOffset + 7));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_inst_table_insert_logs;
    }

    gregs[REG_RAX] = static_cast<greg_t>(object_pair);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmInstTableInsertReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropDescriptorLookupProbeOffset ||
      libroblox_offset == kStage6RbxmPropDescriptorLookupProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t descriptor = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t property_table = static_cast<uintptr_t>(gregs[REG_R15]);
    const uintptr_t class_descriptor =
        property_table >= 0x278 ? property_table - 0x278 : 0;
    char property_name[160];
    ReadLibcxxStringPreview(rbp - 0x300, property_name, sizeof(property_name));
    const uintptr_t descriptor_entry0 = ReadPointerIfReadable(descriptor);
    if (std::strcmp(property_name, "Name") == 0 && descriptor_entry0 != 0 &&
        IsLikelyCallableRbxmPropertyDescriptor(descriptor_entry0)) {
      RepairStage6RbxmNameDescriptorForRbxmApply(descriptor_entry0,
                                                 "prop-descriptor-lookup");
    } else if (std::strcmp(property_name, "Name") == 0 &&
               descriptor_entry0 != 0) {
      LogRbxmPropertyDescriptorCandidateReject(
          "Name", "prop-descriptor-lookup-entry0", descriptor_entry0);
    }
    static volatile sig_atomic_t rbxm_inst_class_lookup_logs = 0;
    if (rbxm_inst_class_lookup_logs < 16) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "prop-descriptor-lookup inst-class-lookup off=0x%lx rbp=%p "
          "property_name=\"%s\" class_descriptor=%p property_table=%p "
          "table_fields{0=0x%x 8=%p 10=%p 18=0x%x 1c=0x%x} "
          "descriptor=%p entry0=%p entry8=%p next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6RbxmPropDescriptorLookupProbeOffset),
          reinterpret_cast<void*>(rbp), property_name,
          reinterpret_cast<void*>(class_descriptor),
          reinterpret_cast<void*>(property_table),
          IsReadableMemoryRange(property_table + 0x00, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(property_table + 0x00)
              : 0xffffffffu,
          reinterpret_cast<void*>(ReadPointerIfReadable(property_table + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(property_table + 0x10)),
          IsReadableMemoryRange(property_table + 0x18, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(property_table + 0x18)
              : 0xffffffffu,
          IsReadableMemoryRange(property_table + 0x1c, sizeof(uint32_t))
              ? *reinterpret_cast<const uint32_t*>(property_table + 0x1c)
              : 0xffffffffu,
          reinterpret_cast<void*>(descriptor),
          reinterpret_cast<void*>(descriptor_entry0),
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x08)),
          static_cast<unsigned long>(descriptor == 0 ? 0x2de9565 : 0x2de955b));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_inst_class_lookup_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + (descriptor == 0 ? 0x2de9565 : 0x2de955b));
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropApplyCallProbeOffset ||
      libroblox_offset == kStage6RbxmPropApplyCallProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t rsp = static_cast<uintptr_t>(gregs[REG_RSP]);
    const uintptr_t error_object = static_cast<uintptr_t>(gregs[REG_RDI]);
    const uintptr_t stream_vector = static_cast<uintptr_t>(gregs[REG_RSI]);
    const uintptr_t descriptor = static_cast<uintptr_t>(gregs[REG_RDX]);
    const uintptr_t value_context = static_cast<uintptr_t>(gregs[REG_RCX]);
    const uintptr_t object_vector = static_cast<uintptr_t>(gregs[REG_R8]);
    const uintptr_t aux_vector = static_cast<uintptr_t>(gregs[REG_R9]);
    const uintptr_t object_table = ReadPointerIfReadable(object_vector);
    const uintptr_t stack0 = ReadPointerIfReadable(rsp + 0x00);
    const uintptr_t stack1 = ReadPointerIfReadable(rsp + 0x08);
    const uintptr_t stack2 = ReadPointerIfReadable(rsp + 0x10);
    const uintptr_t stack3 = ReadPointerIfReadable(rsp + 0x18);
    const uintptr_t stack4 = ReadPointerIfReadable(rsp + 0x20);
    const uintptr_t stack5 = ReadPointerIfReadable(rsp + 0x28);
    const uintptr_t stack6 = ReadPointerIfReadable(rsp + 0x30);

    char property_name[160];
    char descriptor_name[160];
    char descriptor_preview[180];
    char value_preview[180];
    char value_strings_preview[1000];
    char stream_preview[180];
    char aux_preview[180];
    ReadLibcxxStringPreview(rbp - 0x300, property_name, sizeof(property_name));
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadMemoryHexPreview(descriptor, descriptor_preview,
                         sizeof(descriptor_preview));
    ReadMemoryHexPreview(value_context, value_preview, sizeof(value_preview));
    ReadRbxmValueContextStringVectorPreview(
        value_context, value_strings_preview, sizeof(value_strings_preview));
    ReadMemoryHexPreview(stream_vector, stream_preview, sizeof(stream_preview));
    ReadMemoryHexPreview(aux_vector, aux_preview, sizeof(aux_preview));
    const bool is_name_property = std::strcmp(property_name, "Name") == 0 ||
                                  std::strcmp(descriptor_name, "Name") == 0;

    auto read_object_sample = [&](uint32_t id, char* out, size_t out_size) {
      if (out == nullptr || out_size == 0) {
        return;
      }
      out[0] = '\0';
      const uintptr_t object_slot =
          object_table + static_cast<uintptr_t>(id) * 0x10;
      const uintptr_t object_pair = ReadPointerIfReadable(object_slot);
      const uintptr_t object_ref = ReadPointerIfReadable(object_slot + 0x08);
      char name_slot_preview[260];
      ReadRbxmInstanceNameSlotPreview(object_pair, name_slot_preview,
                                      sizeof(name_slot_preview));
      std::snprintf(out, out_size, "id=%u{slot=%p pair=%p ref=%p %s}", id,
                    reinterpret_cast<void*>(object_slot),
                    reinterpret_cast<void*>(object_pair),
                    reinterpret_cast<void*>(object_ref), name_slot_preview);
    };

    static volatile sig_atomic_t rbxm_prop_apply_call_logs = 0;
    static volatile sig_atomic_t rbxm_prop_apply_call_name_logs = 0;
    if (rbxm_prop_apply_call_logs < 32 ||
        (is_name_property && rbxm_prop_apply_call_name_logs < 128)) {
      char sample0[360];
      char sample1[360];
      char sample8[360];
      char sample10[360];
      read_object_sample(0, sample0, sizeof(sample0));
      read_object_sample(1, sample1, sizeof(sample1));
      read_object_sample(8, sample8, sizeof(sample8));
      read_object_sample(10, sample10, sizeof(sample10));

      char msg[5600];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step prop-apply-call "
          "off=0x%lx rbp=%p property_name=\"%s\" descriptor=%p "
          "descriptor_name=\"%s\" descriptor_entry0=%p "
          "apply_args{rdi=%p rsi=%p rdx=%p rcx=%p r8=%p r9=%p "
          "stack=%p,%p,%p,%p,%p,%p,%p} "
          "previews{descriptor=\"%s\" value_context=\"%s\" "
          "value_context_strings=\"%s\" stream=\"%s\" aux=\"%s\"} "
          "object_table=%p table_count=%llu "
          "vectors{380x10=%llu 3c0x10=%llu 430x1=%llu 50x4=%llu} "
          "samples[%s %s %s %s] call_target=0x2decdec return=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmPropApplyCallProbeOffset),
          reinterpret_cast<void*>(rbp), property_name,
          reinterpret_cast<void*>(descriptor), descriptor_name,
          reinterpret_cast<void*>(ReadPointerIfReadable(descriptor)),
          reinterpret_cast<void*>(error_object),
          reinterpret_cast<void*>(stream_vector),
          reinterpret_cast<void*>(descriptor),
          reinterpret_cast<void*>(value_context),
          reinterpret_cast<void*>(object_vector),
          reinterpret_cast<void*>(aux_vector), reinterpret_cast<void*>(stack0),
          reinterpret_cast<void*>(stack1), reinterpret_cast<void*>(stack2),
          reinterpret_cast<void*>(stack3), reinterpret_cast<void*>(stack4),
          reinterpret_cast<void*>(stack5), reinterpret_cast<void*>(stack6),
          descriptor_preview, value_preview, value_strings_preview,
          stream_preview, aux_preview, reinterpret_cast<void*>(object_table),
          ReadVectorElementCountIfReadable(object_vector, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x3c0, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x430, 0x01),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04), sample0, sample1,
          sample8, sample10,
          static_cast<unsigned long>(kStage6RbxmPropApplyReturnProbeOffset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prop_apply_call_logs;
      if (is_name_property) {
        ++rbxm_prop_apply_call_name_logs;
      }
    }

    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(rsp - sizeof(uintptr_t)))) {
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
          libroblox_base + kStage6RbxmPropApplyReturnProbeOffset;
      gregs[REG_RSP] = static_cast<greg_t>(rsp - sizeof(uintptr_t));
      gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + 0x2decdec);
      return true;
    }
  }

  if (libroblox_offset == kStage6RbxmPropertyApplyStreamByteProbeOffset ||
      libroblox_offset == kStage6RbxmPropertyApplyStreamByteProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t stream_data = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t stream_index = static_cast<uintptr_t>(gregs[REG_RCX]);
    const uintptr_t stream_limit = static_cast<uintptr_t>(gregs[REG_R8]);
    const uintptr_t stream_vector = static_cast<uintptr_t>(gregs[REG_R12]);
    const unsigned int stream_byte =
        static_cast<unsigned int>(gregs[REG_R14]) & 0xffu;
    const uintptr_t descriptor = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t descriptor_type = ReadPointerIfReadable(descriptor + 0x60);
    const uintptr_t value_context = ReadPointerIfReadable(rbp - 0x3e8);
    const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
    const unsigned int error_state =
        IsReadableMemoryRange(rbp - 0x110, 1)
            ? *reinterpret_cast<const unsigned char*>(rbp - 0x110)
            : 0xffu;

    char descriptor_name[160];
    char descriptor_type_name[160];
    char value_strings_preview[900];
    char stream_preview[180];
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadRbxmDescriptorNameCandidate(descriptor_type, descriptor_type_name,
                                    sizeof(descriptor_type_name));
    ReadRbxmValueContextStringVectorPreview(
        value_context, value_strings_preview, sizeof(value_strings_preview));
    ReadMemoryHexPreview(stream_vector, stream_preview, sizeof(stream_preview));
    const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;

    static volatile sig_atomic_t rbxm_apply_stream_byte_logs = 0;
    static volatile sig_atomic_t rbxm_apply_stream_byte_name_logs = 0;
    if (rbxm_apply_stream_byte_logs < 48 ||
        (is_name_property && rbxm_apply_stream_byte_name_logs < 256)) {
      char msg[2600];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "property-apply-stream-byte off=0x%lx rbp=%p "
          "descriptor=%p descriptor_name=\"%s\" descriptor_type=%p "
          "descriptor_type_name=\"%s\" byte=0x%x signed=%d "
          "stream{vector=%p data=%p index=%llu limit=%llu remaining=%lld "
          "raw=\"%s\"} error_state=0x%x value_context=%p "
          "value_context_strings=\"%s\" object_vector=%p next=0x2decebc\n",
          static_cast<unsigned long>(
              kStage6RbxmPropertyApplyStreamByteProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(descriptor),
          descriptor_name, reinterpret_cast<void*>(descriptor_type),
          descriptor_type_name, stream_byte,
          static_cast<int>(static_cast<signed char>(stream_byte)),
          reinterpret_cast<void*>(stream_vector),
          reinterpret_cast<void*>(stream_data),
          static_cast<unsigned long long>(stream_index),
          static_cast<unsigned long long>(stream_limit),
          static_cast<long long>(stream_limit) -
              static_cast<long long>(stream_index),
          stream_preview, error_state, reinterpret_cast<void*>(value_context),
          value_strings_preview, reinterpret_cast<void*>(object_vector));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_apply_stream_byte_logs;
      if (is_name_property) {
        ++rbxm_apply_stream_byte_name_logs;
      }
    }

    if (IsReadableMemoryRange(rbp - 0x130, 1)) {
      *reinterpret_cast<unsigned char*>(rbp - 0x130) = 0;
    }
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + 0x2decebc);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropertyApplyLoopDecisionProbeOffset ||
      libroblox_offset == kStage6RbxmPropertyApplyLoopDecisionProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const unsigned int r14d = static_cast<unsigned int>(gregs[REG_R14]);
    const uintptr_t descriptor = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t descriptor_type = ReadPointerIfReadable(descriptor + 0x60);
    const uintptr_t value_context = ReadPointerIfReadable(rbp - 0x3e8);
    const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
    const uintptr_t next_offset = r14d == 0 ? 0x2dece70 : 0x2ded719;
    const unsigned int local_tag =
        IsReadableMemoryRange(rbp - 0x1a0, 1)
            ? *reinterpret_cast<const unsigned char*>(rbp - 0x1a0)
            : 0xffu;
    const unsigned int local_live =
        IsReadableMemoryRange(rbp - 0x178, 1)
            ? *reinterpret_cast<const unsigned char*>(rbp - 0x178)
            : 0xffu;

    char descriptor_name[160];
    char descriptor_type_name[160];
    char value_strings_preview[900];
    char variant_preview[180];
    char token_preview[180];
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadRbxmDescriptorNameCandidate(descriptor_type, descriptor_type_name,
                                    sizeof(descriptor_type_name));
    ReadRbxmValueContextStringVectorPreview(
        value_context, value_strings_preview, sizeof(value_strings_preview));
    ReadMemoryHexPreview(rbp - 0x1a0, variant_preview, sizeof(variant_preview));
    ReadMemoryHexPreview(rbp - 0x130, token_preview, sizeof(token_preview));
    const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;

    static volatile sig_atomic_t rbxm_apply_loop_decision_logs = 0;
    static volatile sig_atomic_t rbxm_apply_loop_decision_name_logs = 0;
    if (rbxm_apply_loop_decision_logs < 48 ||
        (is_name_property && rbxm_apply_loop_decision_name_logs < 256)) {
      char msg[3000];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "property-apply-loop-decision off=0x%lx rbp=%p r14d=0x%x "
          "descriptor=%p descriptor_name=\"%s\" descriptor_type=%p "
          "descriptor_type_name=\"%s\" local_tag=0x%x local_live=0x%x "
          "token_raw=\"%s\" variant_raw=\"%s\" value_context=%p "
          "value_context_strings=\"%s\" object_vector=%p object_count=%llu "
          "next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6RbxmPropertyApplyLoopDecisionProbeOffset),
          reinterpret_cast<void*>(rbp), r14d,
          reinterpret_cast<void*>(descriptor), descriptor_name,
          reinterpret_cast<void*>(descriptor_type), descriptor_type_name,
          local_tag, local_live, token_preview, variant_preview,
          reinterpret_cast<void*>(value_context), value_strings_preview,
          reinterpret_cast<void*>(object_vector),
          ReadVectorElementCountIfReadable(object_vector, 0x10),
          static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_apply_loop_decision_logs;
      if (is_name_property) {
        ++rbxm_apply_loop_decision_name_logs;
      }
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropertyApplyTypeBranchProbeOffset ||
      libroblox_offset == kStage6RbxmPropertyApplyTypeBranchProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const unsigned int r14d = static_cast<unsigned int>(gregs[REG_R14]);
    const uintptr_t descriptor = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t descriptor_type = ReadPointerIfReadable(descriptor + 0x60);
    const uintptr_t value_context = ReadPointerIfReadable(rbp - 0x3e8);
    const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
    const uintptr_t next_offset = r14d == 1 ? 0x2dee569 : 0x2ded723;
    const uint32_t descriptor_type_field30 =
        IsReadableMemoryRange(descriptor_type + 0x30, sizeof(uint32_t))
            ? *reinterpret_cast<const uint32_t*>(descriptor_type + 0x30)
            : 0xffffffffu;

    char descriptor_name[160];
    char descriptor_type_name[160];
    char value_strings_preview[900];
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadRbxmDescriptorNameCandidate(descriptor_type, descriptor_type_name,
                                    sizeof(descriptor_type_name));
    ReadRbxmValueContextStringVectorPreview(
        value_context, value_strings_preview, sizeof(value_strings_preview));
    const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;

    static volatile sig_atomic_t rbxm_apply_type_branch_logs = 0;
    static volatile sig_atomic_t rbxm_apply_type_branch_name_logs = 0;
    if (rbxm_apply_type_branch_logs < 32 ||
        (is_name_property && rbxm_apply_type_branch_name_logs < 160)) {
      char msg[2400];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "property-apply-type-branch off=0x%lx rbp=%p r14d=0x%x "
          "descriptor=%p descriptor_name=\"%s\" descriptor_type=%p "
          "descriptor_type_name=\"%s\" descriptor_type_field30=0x%x "
          "value_context=%p value_context_strings=\"%s\" object_vector=%p "
          "object_count=%llu next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6RbxmPropertyApplyTypeBranchProbeOffset),
          reinterpret_cast<void*>(rbp), r14d,
          reinterpret_cast<void*>(descriptor), descriptor_name,
          reinterpret_cast<void*>(descriptor_type), descriptor_type_name,
          descriptor_type_field30, reinterpret_cast<void*>(value_context),
          value_strings_preview, reinterpret_cast<void*>(object_vector),
          ReadVectorElementCountIfReadable(object_vector, 0x10),
          static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_apply_type_branch_logs;
      if (is_name_property) {
        ++rbxm_apply_type_branch_name_logs;
      }
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropertySetterModeBranchProbeOffset ||
      libroblox_offset == kStage6RbxmPropertySetterModeBranchProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t descriptor = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t value_context = ReadPointerIfReadable(rbp - 0x3e8);
    const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
    const uintptr_t object_table = ReadPointerIfReadable(object_vector);
    const unsigned int mode =
        IsReadableMemoryRange(rbp - 0x404, 1)
            ? *reinterpret_cast<const unsigned char*>(rbp - 0x404)
            : 0xffu;
    const uintptr_t descriptor_type = ReadPointerIfReadable(descriptor + 0x60);
    const unsigned int descriptor_flag87 =
        IsReadableMemoryRange(descriptor + 0x87, 1)
            ? *reinterpret_cast<const unsigned char*>(descriptor + 0x87)
            : 0xffu;
    const uintptr_t next_offset = mode == 1 ? 0x2ded1cf : 0x2ded4c2;

    char descriptor_name[160];
    char descriptor_type_name[160];
    char value_preview[180];
    char value_strings_preview[1000];
    char sample0[360];
    char sample1[360];
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadRbxmDescriptorNameCandidate(descriptor_type, descriptor_type_name,
                                    sizeof(descriptor_type_name));
    ReadMemoryHexPreview(value_context, value_preview, sizeof(value_preview));
    ReadRbxmValueContextStringVectorPreview(
        value_context, value_strings_preview, sizeof(value_strings_preview));
    auto read_object_sample = [&](uint32_t id, char* out, size_t out_size) {
      if (out == nullptr || out_size == 0) {
        return;
      }
      out[0] = '\0';
      const uintptr_t object_slot =
          object_table + static_cast<uintptr_t>(id) * 0x10;
      const uintptr_t object_pair = ReadPointerIfReadable(object_slot);
      const uintptr_t object_ref = ReadPointerIfReadable(object_slot + 0x08);
      char name_slot_preview[260];
      ReadRbxmInstanceNameSlotPreview(object_pair, name_slot_preview,
                                      sizeof(name_slot_preview));
      std::snprintf(out, out_size, "id=%u{slot=%p pair=%p ref=%p %s}", id,
                    reinterpret_cast<void*>(object_slot),
                    reinterpret_cast<void*>(object_pair),
                    reinterpret_cast<void*>(object_ref), name_slot_preview);
    };
    read_object_sample(0, sample0, sizeof(sample0));
    read_object_sample(1, sample1, sizeof(sample1));

    const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;
    static volatile sig_atomic_t rbxm_property_setter_mode_logs = 0;
    static volatile sig_atomic_t rbxm_property_setter_mode_name_logs = 0;
    if (rbxm_property_setter_mode_logs < 16 ||
        (is_name_property && rbxm_property_setter_mode_name_logs < 160)) {
      char msg[3600];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "property-setter-mode-branch off=0x%lx rbp=%p mode=0x%x "
          "descriptor=%p descriptor_name=\"%s\" descriptor_type=%p "
          "descriptor_type_name=\"%s\" descriptor_flag87=0x%x "
          "value_context=%p value_context_raw=\"%s\" "
          "value_context_strings=\"%s\" object_vector=%p object_table=%p "
          "object_count=%llu samples[%s %s] next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6RbxmPropertySetterModeBranchProbeOffset),
          reinterpret_cast<void*>(rbp), mode,
          reinterpret_cast<void*>(descriptor), descriptor_name,
          reinterpret_cast<void*>(descriptor_type), descriptor_type_name,
          descriptor_flag87, reinterpret_cast<void*>(value_context),
          value_preview, value_strings_preview,
          reinterpret_cast<void*>(object_vector),
          reinterpret_cast<void*>(object_table),
          ReadVectorElementCountIfReadable(object_vector, 0x10), sample0,
          sample1, static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_property_setter_mode_logs;
      if (is_name_property) {
        ++rbxm_property_setter_mode_name_logs;
      }
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropertySetterCallProbeOffset ||
      libroblox_offset == kStage6RbxmPropertySetterCallProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t rsp = static_cast<uintptr_t>(gregs[REG_RSP]);
    const uintptr_t descriptor = static_cast<uintptr_t>(gregs[REG_RDI]);
    const uintptr_t object = static_cast<uintptr_t>(gregs[REG_RSI]);
    const uintptr_t value_variant = static_cast<uintptr_t>(gregs[REG_RDX]);
    const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
    const uintptr_t object_table = ReadPointerIfReadable(object_vector);
    const unsigned long long object_count =
        ReadVectorElementCountIfReadable(object_vector, 0x10);
    uint32_t object_id = 0xffffffffu;
    const unsigned long long scan_count = std::min(object_count, 5000ULL);
    for (unsigned long long i = 0; i < scan_count; ++i) {
      if (ReadPointerIfReadable(object_table +
                                static_cast<uintptr_t>(i) * 0x10) == object) {
        object_id = static_cast<uint32_t>(i);
        break;
      }
    }

    char descriptor_name[160];
    char value_variant_preview[180];
    char value_string_preview[240];
    char object_name_preview[280];
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    ReadMemoryHexPreview(value_variant, value_variant_preview,
                         sizeof(value_variant_preview));
    ReadLibcxxStringPreview(value_variant + 0x08, value_string_preview,
                            sizeof(value_string_preview));
    ReadRbxmInstanceNameSlotPreview(object, object_name_preview,
                                    sizeof(object_name_preview));
    const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;

    static volatile sig_atomic_t rbxm_property_setter_call_logs = 0;
    static volatile sig_atomic_t rbxm_property_setter_name_logs = 0;
    if (rbxm_property_setter_call_logs < 16 ||
        (is_name_property && rbxm_property_setter_name_logs < 160)) {
      char msg[2200];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step property-setter-call "
          "off=0x%lx rbp=%p descriptor=%p descriptor_name=\"%s\" "
          "object=%p object_id=%u object_vector=%p object_table=%p "
          "object_count=%llu value_variant=%p value_variant_raw=\"%s\" "
          "value_variant_string=\"%s\" before_%s call_target=0x2df82c8 "
          "return=0x2ded26d\n",
          static_cast<unsigned long>(kStage6RbxmPropertySetterCallProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(descriptor),
          descriptor_name, reinterpret_cast<void*>(object), object_id,
          reinterpret_cast<void*>(object_vector),
          reinterpret_cast<void*>(object_table), object_count,
          reinterpret_cast<void*>(value_variant), value_variant_preview,
          value_string_preview, object_name_preview);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_property_setter_call_logs;
      if (is_name_property) {
        ++rbxm_property_setter_name_logs;
      }
    }

    if (rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(rsp - sizeof(uintptr_t)))) {
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
          libroblox_base + 0x2ded26d;
      gregs[REG_RSP] = static_cast<greg_t>(rsp - sizeof(uintptr_t));
      gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + 0x2df82c8);
      return true;
    }
  }

  if (libroblox_offset == kStage6RbxmGenericSetterCallProbeOffset ||
      libroblox_offset == kStage6RbxmGenericSetterCallProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t rsp = static_cast<uintptr_t>(gregs[REG_RSP]);
    const unsigned long long context_index =
        static_cast<unsigned long long>(gregs[REG_RBX]);
    const uintptr_t call_table = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t descriptor = static_cast<uintptr_t>(gregs[REG_RDI]);
    const uintptr_t object = static_cast<uintptr_t>(gregs[REG_RSI]);
    const uintptr_t value_variant = static_cast<uintptr_t>(gregs[REG_RDX]);
    const uintptr_t target = ReadPointerIfReadable(call_table + 0xd0);

    const bool trace_datamodel_patch_load_steps =
        IsEnabled("MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_LOAD_STEPS");

    static volatile sig_atomic_t rbxm_generic_setter_call_logs = 0;
    if (trace_datamodel_patch_load_steps &&
        rbxm_generic_setter_call_logs < 48) {
      char descriptor_name[160];
      char value_string_preview[260];
      ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                      sizeof(descriptor_name));
      ReadLibcxxStringPreview(value_variant, value_string_preview,
                              sizeof(value_string_preview));
      const bool is_name_property = std::strcmp(descriptor_name, "Name") == 0;
      if (is_name_property) {
        CacheStage6RbxmNameDescriptor(descriptor);
      }
      const bool is_interesting_name =
          is_name_property &&
          (context_index < 6 ||
           std::strcmp(value_string_preview, "PatchRoot") == 0 ||
           std::strcmp(value_string_preview, "DataModelInstances") == 0 ||
           std::strcmp(value_string_preview, "CorePackages") == 0 ||
           std::strcmp(value_string_preview, "CoreScripts") == 0);
      if (is_interesting_name) {
        const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
        const uintptr_t object_table = ReadPointerIfReadable(object_vector);
        const unsigned long long object_count =
            ReadVectorElementCountIfReadable(object_vector, 0x10);
        uint32_t object_id = 0xffffffffu;
        const unsigned long long scan_count = std::min(object_count, 5000ULL);
        for (unsigned long long i = 0; i < scan_count; ++i) {
          if (ReadPointerIfReadable(object_table + static_cast<uintptr_t>(i) *
                                                       0x10) == object) {
            object_id = static_cast<uint32_t>(i);
            break;
          }
        }
        char value_variant_preview[180];
        char object_name_preview[280];
        ReadMemoryHexPreview(value_variant, value_variant_preview,
                             sizeof(value_variant_preview));
        ReadRbxmInstanceNameSlotPreview(object, object_name_preview,
                                        sizeof(object_name_preview));
        char msg[2400];
        int len = snprintf(
            msg, sizeof(msg),
            "  [trace] Stage6 DataModel patch load step "
            "property-generic-setter-call off=0x%lx rbp=%p "
            "descriptor=%p descriptor_name=\"%s\" context_index=%llu "
            "object=%p object_id=%u "
            "object_vector=%p object_table=%p object_count=%llu "
            "value_variant=%p value_variant_raw=\"%s\" "
            "value_variant_string=\"%s\" before_%s call_table=%p "
            "call_target=%p return=0x2dedae2\n",
            static_cast<unsigned long>(kStage6RbxmGenericSetterCallProbeOffset),
            reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(descriptor),
            descriptor_name, context_index, reinterpret_cast<void*>(object),
            object_id, reinterpret_cast<void*>(object_vector),
            reinterpret_cast<void*>(object_table), object_count,
            reinterpret_cast<void*>(value_variant), value_variant_preview,
            value_string_preview, object_name_preview,
            reinterpret_cast<void*>(call_table),
            reinterpret_cast<void*>(target));
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++rbxm_generic_setter_call_logs;
      }
    }

    if (target != 0 && rsp >= sizeof(uintptr_t) &&
        IsReadableMemoryRange(rsp - sizeof(uintptr_t), sizeof(uintptr_t)) &&
        EnsureWritablePage(reinterpret_cast<void*>(rsp - sizeof(uintptr_t)))) {
      *reinterpret_cast<uintptr_t*>(rsp - sizeof(uintptr_t)) =
          libroblox_base + 0x2dedae2;
      gregs[REG_RSP] = static_cast<greg_t>(rsp - sizeof(uintptr_t));
      gregs[REG_RIP] = static_cast<greg_t>(target);
      return true;
    }
  }

  if (libroblox_offset == kStage6RbxmGenericSetterReturnProbeOffset ||
      libroblox_offset == kStage6RbxmGenericSetterReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const unsigned long long context_index =
        static_cast<unsigned long long>(gregs[REG_RBX]);
    const uintptr_t descriptor = ReadPointerIfReadable(rbp - 0x3f8);
    const uintptr_t object = static_cast<uintptr_t>(gregs[REG_R15]);
    const uintptr_t value_variant = rbp - 0x1f0;

    const bool is_name_property = IsCachedStage6RbxmNameDescriptor(descriptor);
    const bool repaired_name_slot =
        is_name_property && RepairStage6RbxmInstanceNameSlotFromValue(
                                object, value_variant, "generic-setter-return");
    const bool trace_datamodel_patch_load_steps =
        IsEnabled("MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_LOAD_STEPS");

    static volatile sig_atomic_t rbxm_generic_setter_return_logs = 0;
    if (trace_datamodel_patch_load_steps &&
        rbxm_generic_setter_return_logs < 48) {
      char descriptor_name[160];
      bool trace_name_property = is_name_property;
      if (is_name_property) {
        std::snprintf(descriptor_name, sizeof(descriptor_name), "Name");
      } else {
        ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                        sizeof(descriptor_name));
        trace_name_property = std::strcmp(descriptor_name, "Name") == 0;
        if (trace_name_property) {
          CacheStage6RbxmNameDescriptor(descriptor);
        }
      }
      char value_string_preview[260];
      ReadLibcxxStringPreview(value_variant, value_string_preview,
                              sizeof(value_string_preview));
      const bool is_interesting_name =
          trace_name_property &&
          (context_index < 6 ||
           std::strcmp(value_string_preview, "PatchRoot") == 0 ||
           std::strcmp(value_string_preview, "DataModelInstances") == 0 ||
           std::strcmp(value_string_preview, "CorePackages") == 0 ||
           std::strcmp(value_string_preview, "CoreScripts") == 0);
      if (is_interesting_name) {
        const uintptr_t object_vector = ReadPointerIfReadable(rbp - 0x418);
        const uintptr_t object_table = ReadPointerIfReadable(object_vector);
        const unsigned long long object_count =
            ReadVectorElementCountIfReadable(object_vector, 0x10);
        uint32_t object_id = 0xffffffffu;
        const unsigned long long scan_count = std::min(object_count, 5000ULL);
        for (unsigned long long i = 0; i < scan_count; ++i) {
          if (ReadPointerIfReadable(object_table + static_cast<uintptr_t>(i) *
                                                       0x10) == object) {
            object_id = static_cast<uint32_t>(i);
            break;
          }
        }
        char object_name_preview[280];
        char object_preview[180];
        char string_fields_preview[1200];
        ReadRbxmInstanceNameSlotPreview(object, object_name_preview,
                                        sizeof(object_name_preview));
        ReadMemoryHexPreview(object, object_preview, sizeof(object_preview));
        ReadRbxmInstanceStringFieldCandidatesPreview(
            object, string_fields_preview, sizeof(string_fields_preview));
        char msg[2600];
        int len = snprintf(
            msg, sizeof(msg),
            "  [trace] Stage6 DataModel patch load step "
            "property-generic-setter-return off=0x%lx rbp=%p "
            "descriptor=%p descriptor_name=\"%s\" context_index=%llu "
            "object=%p object_id=%u object_raw=\"%s\" "
            "value_variant=%p value_variant_string=\"%s\" after_%s "
            "%s repaired=%d next=0x2dedae5\n",
            static_cast<unsigned long>(
                kStage6RbxmGenericSetterReturnProbeOffset),
            reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(descriptor),
            descriptor_name, context_index, reinterpret_cast<void*>(object),
            object_id, object_preview, reinterpret_cast<void*>(value_variant),
            value_string_preview, object_name_preview, string_fields_preview,
            repaired_name_slot ? 1 : 0);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
        ++rbxm_generic_setter_return_logs;
      }
    }

    gregs[REG_RBX] = static_cast<greg_t>(context_index + 1);
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + 0x2dedae5);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPropApplyReturnProbeOffset ||
      libroblox_offset == kStage6RbxmPropApplyReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t error_object = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t descriptor = static_cast<uintptr_t>(gregs[REG_R15]);
    const unsigned int error_flag =
        IsReadableMemoryRange(error_object + 0x20, 1)
            ? *reinterpret_cast<const unsigned char*>(error_object + 0x20)
            : 0xffu;
    const unsigned int descriptor_flag87 =
        IsReadableMemoryRange(descriptor + 0x87, 1)
            ? *reinterpret_cast<const unsigned char*>(descriptor + 0x87)
            : 0xffu;
    const uintptr_t object_table = ReadPointerIfReadable(rbp - 0x380);
    const uintptr_t next_offset = error_flag == 0 ? 0x2de9565 : 0x2de9bc8;

    char property_name[160];
    char descriptor_name[160];
    ReadLibcxxStringPreview(rbp - 0x300, property_name, sizeof(property_name));
    ReadRbxmDescriptorNameCandidate(descriptor, descriptor_name,
                                    sizeof(descriptor_name));
    const bool is_name_property = std::strcmp(property_name, "Name") == 0 ||
                                  std::strcmp(descriptor_name, "Name") == 0;

    auto read_object_sample = [&](uint32_t id, char* out, size_t out_size) {
      if (out == nullptr || out_size == 0) {
        return;
      }
      out[0] = '\0';
      const uintptr_t object_slot =
          object_table + static_cast<uintptr_t>(id) * 0x10;
      const uintptr_t object_pair = ReadPointerIfReadable(object_slot);
      const uintptr_t object_ref = ReadPointerIfReadable(object_slot + 0x08);
      char name_slot_preview[260];
      ReadRbxmInstanceNameSlotPreview(object_pair, name_slot_preview,
                                      sizeof(name_slot_preview));
      std::snprintf(out, out_size, "id=%u{slot=%p pair=%p ref=%p %s}", id,
                    reinterpret_cast<void*>(object_slot),
                    reinterpret_cast<void*>(object_pair),
                    reinterpret_cast<void*>(object_ref), name_slot_preview);
    };

    static volatile sig_atomic_t rbxm_prop_apply_return_logs = 0;
    static volatile sig_atomic_t rbxm_prop_apply_name_logs = 0;
    const bool should_log =
        rbxm_prop_apply_return_logs < 32 || error_flag == 0 ||
        (is_name_property && rbxm_prop_apply_name_logs < 128);
    if (should_log) {
      char sample0[360];
      char sample1[360];
      char sample8[360];
      char sample10[360];
      read_object_sample(0, sample0, sizeof(sample0));
      read_object_sample(1, sample1, sizeof(sample1));
      read_object_sample(8, sample8, sizeof(sample8));
      read_object_sample(10, sample10, sizeof(sample10));

      char msg[3600];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step prop-apply-return "
          "off=0x%lx rbp=%p property_name=\"%s\" descriptor=%p "
          "descriptor_name=\"%s\" descriptor_flag87=0x%x error=%p "
          "error_flag=0x%x object_table=%p table_count=%llu "
          "vectors{380x10=%llu 3c0x10=%llu 430x1=%llu 50x4=%llu} "
          "samples[%s %s %s %s] next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmPropApplyReturnProbeOffset),
          reinterpret_cast<void*>(rbp), property_name,
          reinterpret_cast<void*>(descriptor), descriptor_name,
          descriptor_flag87, reinterpret_cast<void*>(error_object), error_flag,
          reinterpret_cast<void*>(object_table),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x3c0, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x430, 0x01),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04), sample0, sample1,
          sample8, sample10, static_cast<unsigned long>(next_offset));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prop_apply_return_logs;
      if (is_name_property) {
        ++rbxm_prop_apply_name_logs;
      }
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPrntChildIdsReturnProbeOffset ||
      libroblox_offset == kStage6RbxmPrntChildIdsReturnProbeOffset + 1 ||
      libroblox_offset == kStage6RbxmPrntParentIdsReturnProbeOffset ||
      libroblox_offset == kStage6RbxmPrntParentIdsReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const bool is_parent =
        libroblox_offset == kStage6RbxmPrntParentIdsReturnProbeOffset ||
        libroblox_offset == kStage6RbxmPrntParentIdsReturnProbeOffset + 1;
    const uintptr_t error_object = static_cast<uintptr_t>(gregs[REG_R14]);
    const unsigned int error_flag =
        IsReadableMemoryRange(error_object + 0x20, 1)
            ? *reinterpret_cast<const unsigned char*>(error_object + 0x20)
            : 0xffu;
    const uintptr_t ids_vector = is_parent ? rbp - 0x50 : rbp - 0x300;
    const uintptr_t ids_begin = ReadPointerIfReadable(ids_vector);
    const uintptr_t ids_end = ReadPointerIfReadable(ids_vector + 0x08);
    const uintptr_t ids_cap = ReadPointerIfReadable(ids_vector + 0x10);

    static volatile sig_atomic_t rbxm_prnt_ids_logs = 0;
    if (rbxm_prnt_ids_logs < 16) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step %s "
          "off=0x%lx rbp=%p error=%p error_flag=0x%x count_arg=0x%x "
          "ids{begin=%p end=%p cap=%p count=%llu first=%d second=%d "
          "third=%d} stream{0=%p 8=%p 10=%p 18=%p 20=%p} next=0x%lx\n",
          is_parent ? "prnt-parent-ids-return" : "prnt-child-ids-return",
          static_cast<unsigned long>(
              is_parent ? kStage6RbxmPrntParentIdsReturnProbeOffset
                        : kStage6RbxmPrntChildIdsReturnProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(error_object),
          error_flag, ReadU32IfReadable(rbp - 0x330),
          reinterpret_cast<void*>(ids_begin), reinterpret_cast<void*>(ids_end),
          reinterpret_cast<void*>(ids_cap),
          ReadVectorElementCountIfReadable(ids_vector, 0x04),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x04)),
          static_cast<int32_t>(ReadU32IfReadable(ids_begin + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x430)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x428)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x420)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x418)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x410)),
          static_cast<unsigned long>(
              error_flag == 0 ? (is_parent ? 0x2de9c23 : 0x2de98f7)
                              : (is_parent ? 0x2de9911 : 0x2de94ad)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prnt_ids_logs;
    }

    gregs[REG_RCX] = static_cast<greg_t>(ReadU32IfReadable(rbp - 0x330));
    const uintptr_t next_offset = error_flag == 0
                                      ? (is_parent ? 0x2de9c23 : 0x2de98f7)
                                      : (is_parent ? 0x2de9911 : 0x2de94ad);
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPrntObjectLookupProbeOffset ||
      libroblox_offset == kStage6RbxmPrntObjectLookupProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t loop_index = static_cast<uintptr_t>(gregs[REG_R13]);
    const uintptr_t child_ids = ReadPointerIfReadable(rbp - 0x300);
    const uintptr_t parent_ids = ReadPointerIfReadable(rbp - 0x50);
    const uint32_t child_id =
        ReadU32IfReadable(child_ids + loop_index * sizeof(uint32_t));
    const uint32_t parent_id =
        ReadU32IfReadable(parent_ids + loop_index * sizeof(uint32_t));
    const uintptr_t object_pair = ReadPointerIfReadable(rbp - 0x320);
    const uintptr_t object_ref = ReadPointerIfReadable(rbp - 0x318);
    static volatile sig_atomic_t rbxm_prnt_object_lookup_logs = 0;
    if (rbxm_prnt_object_lookup_logs < 64 ||
        (object_pair != 0 && rbxm_prnt_object_lookup_logs < 160)) {
      char msg[1700];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "prnt-object-lookup off=0x%lx rbp=%p index=%llu child=%d "
          "parent=%d object_pair=%p object_ref=%p instance_table_count=%llu "
          "child_ids_count=%llu parent_ids_count=%llu next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmPrntObjectLookupProbeOffset),
          reinterpret_cast<void*>(rbp),
          static_cast<unsigned long long>(loop_index),
          static_cast<int32_t>(child_id), static_cast<int32_t>(parent_id),
          reinterpret_cast<void*>(object_pair),
          reinterpret_cast<void*>(object_ref),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x300, 0x04),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04),
          static_cast<unsigned long>(object_pair == 0 ? 0x2de9d35 : 0x2de9c83));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prnt_object_lookup_logs;
    }

    gregs[REG_RDI] = static_cast<greg_t>(object_pair);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + (object_pair == 0 ? 0x2de9d35 : 0x2de9c83));
    return true;
  }

  if (libroblox_offset == kStage6RbxmPrntParentBranchProbeOffset ||
      libroblox_offset == kStage6RbxmPrntParentBranchProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t loop_index = static_cast<uintptr_t>(gregs[REG_R13]);
    const uint32_t parent_id =
        static_cast<uint32_t>(static_cast<uintptr_t>(gregs[REG_RDX]));
    const uintptr_t child_ids = ReadPointerIfReadable(rbp - 0x300);
    const uint32_t child_id =
        ReadU32IfReadable(child_ids + loop_index * sizeof(uint32_t));
    const uintptr_t output_holder = ReadPointerIfReadable(rbp - 0x498);
    static volatile sig_atomic_t rbxm_prnt_parent_branch_logs = 0;
    if (rbxm_prnt_parent_branch_logs < 24 || parent_id == 0xffffffffu) {
      char msg[1700];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "prnt-parent-branch off=0x%lx rbp=%p index=%llu child=%d "
          "parent=%d is_root=%d object_pair=%p object_ref=%p "
          "output_holder=%p output_begin=%p output_end=%p output_count=%llu "
          "next=0x%lx\n",
          static_cast<unsigned long>(kStage6RbxmPrntParentBranchProbeOffset),
          reinterpret_cast<void*>(rbp),
          static_cast<unsigned long long>(loop_index),
          static_cast<int32_t>(child_id), static_cast<int32_t>(parent_id),
          parent_id == 0xffffffffu ? 1 : 0,
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x320)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x318)),
          reinterpret_cast<void*>(output_holder),
          reinterpret_cast<void*>(ReadPointerIfReadable(output_holder)),
          reinterpret_cast<void*>(ReadPointerIfReadable(output_holder + 0x08)),
          ReadVectorElementCountIfReadable(output_holder, 0x10),
          static_cast<unsigned long>(parent_id == 0xffffffffu ? 0x2de9cf5
                                                              : 0x2de9c95));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prnt_parent_branch_logs;
    }

    const uintptr_t next_offset =
        parent_id == 0xffffffffu ? 0x2de9cf5 : 0x2de9c95;
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + next_offset);
    return true;
  }

  if (libroblox_offset == kStage6RbxmPrntRootAppendReturnProbeOffset ||
      libroblox_offset == kStage6RbxmPrntRootAppendReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t output_holder = ReadPointerIfReadable(rbp - 0x498);
    static volatile sig_atomic_t rbxm_prnt_root_append_logs = 0;
    if (rbxm_prnt_root_append_logs < 16) {
      char msg[1300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "prnt-root-append-return off=0x%lx rbp=%p output_holder=%p "
          "output_begin=%p output_end=%p output_cap=%p output_count=%llu "
          "root_pair=%p root_ref=%p next=0x2de9d35\n",
          static_cast<unsigned long>(
              kStage6RbxmPrntRootAppendReturnProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(output_holder),
          reinterpret_cast<void*>(ReadPointerIfReadable(output_holder)),
          reinterpret_cast<void*>(ReadPointerIfReadable(output_holder + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(output_holder + 0x10)),
          ReadVectorElementCountIfReadable(output_holder, 0x10),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x320)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x318)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_prnt_root_append_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + 0x2de9d35);
    return true;
  }

  if (libroblox_offset == kStage6RbxmDeserializerSummaryProbeOffset ||
      libroblox_offset == kStage6RbxmDeserializerSummaryProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    uintptr_t error_object = ReadPointerIfReadable(rbp - 0x450);
    if (error_object == 0) {
      error_object = static_cast<uintptr_t>(gregs[REG_R14]);
    }
    const uintptr_t output_holder = ReadPointerIfReadable(rbp - 0x498);
    const uintptr_t output_begin = ReadPointerIfReadable(output_holder);
    const uintptr_t output_end = ReadPointerIfReadable(output_holder + 0x08);
    const uintptr_t output_cap = ReadPointerIfReadable(output_holder + 0x10);
    char chunk_tag[5] = {'\0', '\0', '\0', '\0', '\0'};
    if (IsReadableMemoryRange(rbp - 0xe0, 4)) {
      const auto* raw_tag = reinterpret_cast<const unsigned char*>(rbp - 0xe0);
      for (size_t i = 0; i < 4; ++i) {
        chunk_tag[i] = (raw_tag[i] >= 0x20 && raw_tag[i] <= 0x7e)
                           ? static_cast<char>(raw_tag[i])
                           : '.';
      }
    }

    static volatile sig_atomic_t rbxm_summary_logs = 0;
    if (rbxm_summary_logs < 16) {
      char msg[2300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step "
          "rbxm-deserialize-summary off=0x%lx rbp=%p error=%p "
          "error_flag=0x%x output_holder=%p output_begin=%p "
          "output_end=%p output_cap=%p output_count=%llu "
          "header_counts{60=0x%x 5c=0x%x} chunk{index=%u tag=\"%s\"} "
          "vectors{360x8=%llu 380x10=%llu 3a0x18=%llu "
          "3c0x10=%llu 3e0x10=%llu 430x1=%llu 50x4=%llu} "
          "slots{3f8=%p 3f0=%p 328=%p 320=%p}\n",
          static_cast<unsigned long>(kStage6RbxmDeserializerSummaryProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(error_object),
          IsReadableMemoryRange(error_object + 0x20, 1)
              ? *reinterpret_cast<const unsigned char*>(error_object + 0x20)
              : 0xffu,
          reinterpret_cast<void*>(output_holder),
          reinterpret_cast<void*>(output_begin),
          reinterpret_cast<void*>(output_end),
          reinterpret_cast<void*>(output_cap),
          ReadVectorElementCountIfReadable(output_holder, 0x10),
          ReadU32IfReadable(rbp - 0x60), ReadU32IfReadable(rbp - 0x5c),
          ReadU32IfReadable(rbp - 0x438), chunk_tag,
          ReadVectorElementCountIfReadable(rbp - 0x360, 0x08),
          ReadVectorElementCountIfReadable(rbp - 0x380, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x3a0, 0x18),
          ReadVectorElementCountIfReadable(rbp - 0x3c0, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x3e0, 0x10),
          ReadVectorElementCountIfReadable(rbp - 0x430, 0x01),
          ReadVectorElementCountIfReadable(rbp - 0x50, 0x04),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3f8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3f0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x328)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x320)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++rbxm_summary_logs;
    }

    gregs[REG_RDI] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x3f8));
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6RbxmDeserializerSummaryProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchBuildFallbackStatusProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchBuildFallbackStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t eax = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t parent_input = ReadPointerIfReadable(rbp - 0xf8);
    static volatile sig_atomic_t build_fallback_status_logs = 0;
    if (build_fallback_status_logs < 16) {
      char msg[1200];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step build-fallback-status "
          "off=0x%lx eax=0x%lx rbp=%p parent_input=%p parent_pair=%p "
          "parent_ref=%p list_holder=%p list_begin=%p list_end=%p "
          "out_arg=%p out_pair=%p out_ref=%p\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchBuildFallbackStatusProbeOffset),
          static_cast<unsigned long>(eax & 0xffffffffULL),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(parent_input),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input)),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x58)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x58))),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x58) + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x110)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x110))),
          reinterpret_cast<void*>(ReadPointerIfReadable(
              ReadPointerIfReadable(rbp - 0x110) + 0x08)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++build_fallback_status_logs;
    }

    gregs[REG_R14] = static_cast<greg_t>(eax & 0xffffffffULL);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchBuildFallbackStatusProbeOffset +
        3);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchVerifyBuildStatusProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchVerifyBuildStatusProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t eax = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t verifier_input = static_cast<uintptr_t>(gregs[REG_R14]);
    const uintptr_t out_arg = ReadPointerIfReadable(rbp - 0x110);
    const uintptr_t parent_input = ReadPointerIfReadable(rbp - 0xf8);
    static volatile sig_atomic_t verify_build_status_logs = 0;
    if (verify_build_status_logs < 16) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step verify-build-status "
          "off=0x%lx eax=0x%lx rbp=%p verifier_input=%p out_arg=%p "
          "out_pair=%p out_ref=%p parent_input=%p parent_pair=%p "
          "parent_ref=%p slots{b0=%p a8=%p c0=%p b8=%p f0=%p e8=%p "
          "e0=%p d8=%p a0=%p 98=%p 80=%p 70=%p 68=%p 108=%p "
          "100=%p}\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchVerifyBuildStatusProbeOffset),
          static_cast<unsigned long>(eax & 0xffffffffULL),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(verifier_input),
          reinterpret_cast<void*>(out_arg),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg)),
          reinterpret_cast<void*>(ReadPointerIfReadable(out_arg + 0x08)),
          reinterpret_cast<void*>(parent_input),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input)),
          reinterpret_cast<void*>(ReadPointerIfReadable(parent_input + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xb0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xc0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xb8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xf0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xe0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xd8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x80)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x70)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x108)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x100)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++verify_build_status_logs;
    }

    gregs[REG_R14] = static_cast<greg_t>(eax & 0xffffffffULL);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchVerifyBuildStatusProbeOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchOpenStreamReturnProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchOpenStreamReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    static volatile sig_atomic_t open_stream_logs = 0;
    if (open_stream_logs < 16) {
      char msg[1300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step open-stream "
          "off=0x%lx rbp=%p stream_pair=%p stream_ref=%p path_pair=%p "
          "path_ref=%p configurer=%p provider=%p config=%p "
          "slots{3d0=%p 330=%p 350=%p 468=%p}\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchOpenStreamReturnProbeOffset),
          reinterpret_cast<void*>(rbp),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x2d0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x2c8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5c0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5d8)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x5d0))),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3d0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x330)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x350)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x468)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++open_stream_logs;
    }

    gregs[REG_RDI] = static_cast<greg_t>(rbp - 0x3d0);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchOpenStreamReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchInlineLoadReturnProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchInlineLoadReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    static volatile sig_atomic_t inline_load_logs = 0;
    if (inline_load_logs < 16) {
      const uintptr_t build_input_pair = ReadPointerIfReadable(rbp - 0x4c0);
      const uintptr_t build_input_ref = ReadPointerIfReadable(rbp - 0x4b8);
      const uintptr_t build_input0 = ReadPointerIfReadable(build_input_pair);
      const uintptr_t build_input8 =
          ReadPointerIfReadable(build_input_pair + 0x08);
      const uintptr_t build_input10 =
          ReadPointerIfReadable(build_input_pair + 0x10);
      const uintptr_t build_input18 =
          ReadPointerIfReadable(build_input_pair + 0x18);
      char build_input_preview[180];
      char build_input_ref_preview[180];
      char build_input0_preview[180];
      char build_input8_preview[180];
      char build_input10_preview[180];
      char build_input18_preview[180];
      char build_input_string_preview[160];
      ReadMemoryHexPreview(build_input_pair, build_input_preview,
                           sizeof(build_input_preview));
      ReadMemoryHexPreview(build_input_ref, build_input_ref_preview,
                           sizeof(build_input_ref_preview));
      ReadMemoryHexPreview(build_input0, build_input0_preview,
                           sizeof(build_input0_preview));
      ReadMemoryHexPreview(build_input8, build_input8_preview,
                           sizeof(build_input8_preview));
      ReadMemoryHexPreview(build_input10, build_input10_preview,
                           sizeof(build_input10_preview));
      ReadMemoryHexPreview(build_input18, build_input18_preview,
                           sizeof(build_input18_preview));
      ReadLibcxxStringPreview(build_input_pair, build_input_string_preview,
                              sizeof(build_input_string_preview));
      char msg[4000];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step inline-load "
          "off=0x%lx rbp=%p loaded_pair=%p loaded_ref=%p "
          "stream_pair=%p stream_ref=%p build_input_pair=%p "
          "build_input_ref=%p build_input_preview=\"%s\" "
          "build_input_ref_preview=\"%s\" build_input_string=\"%s\" "
          "build_input0=%p build_input8=%p build_input10=%p "
          "build_input18=%p build_input0_preview=\"%s\" "
          "build_input8_preview=\"%s\" build_input10_preview=\"%s\" "
          "build_input18_preview=\"%s\" "
          "configurer=%p provider=%p config=%p\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchInlineLoadReturnProbeOffset),
          reinterpret_cast<void*>(rbp),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x2d0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x2c8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
          reinterpret_cast<void*>(build_input_pair),
          reinterpret_cast<void*>(build_input_ref), build_input_preview,
          build_input_ref_preview, build_input_string_preview,
          reinterpret_cast<void*>(build_input0),
          reinterpret_cast<void*>(build_input8),
          reinterpret_cast<void*>(build_input10),
          reinterpret_cast<void*>(build_input18), build_input0_preview,
          build_input8_preview, build_input10_preview, build_input18_preview,
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5c0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5d8)),
          reinterpret_cast<void*>(
              ReadPointerIfReadable(ReadPointerIfReadable(rbp - 0x5d0))));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++inline_load_logs;
    }

    gregs[REG_RBX] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x98));
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchInlineLoadReturnProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchInlineBuildResultProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchInlineBuildResultProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t rbx = static_cast<uintptr_t>(gregs[REG_RBX]);
    static volatile sig_atomic_t inline_build_logs = 0;
    if (inline_build_logs < 16) {
      char msg[1500];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step inline-build "
          "off=0x%lx rbp=%p rbx=%p built_pair=%p built_ref=%p "
          "raw_output_pair=%p raw_output_ref=%p stream_pair=%p "
          "stream_ref=%p result_pair=%p result_ref=%p next=0x%lx\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchInlineBuildResultProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(rbx),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3b0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3a8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x330)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x328)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x570)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x568)),
          static_cast<unsigned long>(rbx == 0 ? 0x2462df6 : 0x2462dd1));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++inline_build_logs;
    }

    gregs[REG_RIP] = static_cast<greg_t>(rbx == 0 ? libroblox_base + 0x2462df6
                                                  : libroblox_base + 0x2462dd1);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchVerifyStatusReturnProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchVerifyStatusReturnProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t eax = static_cast<uintptr_t>(gregs[REG_RAX]);
    static volatile sig_atomic_t verify_status_logs = 0;
    if (verify_status_logs < 16) {
      char msg[1300];
      int len =
          snprintf(msg, sizeof(msg),
                   "  [trace] Stage6 DataModel patch load step verify-status "
                   "off=0x%lx eax=0x%lx rbp=%p stream_pair=%p stream_ref=%p "
                   "verified_pair=%p verified_ref=%p fallback_pair=%p "
                   "exception_pair=%p result_pair=%p result_ref=%p\n",
                   static_cast<unsigned long>(
                       kStage6DataModelPatchVerifyStatusReturnProbeOffset),
                   static_cast<unsigned long>(eax & 0xffffffffULL),
                   reinterpret_cast<void*>(rbp),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0xa0)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x98)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x330)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x328)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x350)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x468)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x570)),
                   reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x568)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++verify_status_logs;
    }

    gregs[REG_R12] = static_cast<greg_t>(eax & 0xffffffffULL);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchVerifyStatusReturnProbeOffset +
        3);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchFinalResultProbeOffset ||
      libroblox_offset == kStage6DataModelPatchFinalResultProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t final_result = ReadPointerIfReadable(rbp - 0x570);
    static volatile sig_atomic_t final_result_logs = 0;
    if (final_result_logs < 16) {
      char msg[1300];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch load step final-result "
          "off=0x%lx rbp=%p final_result=%p final_ref=%p "
          "candidate_pair=%p candidate_ref=%p verified_pair=%p verified_ref=%p "
          "loop_state{5f8=%p r14=%p 5c1=0x%x}\n",
          static_cast<unsigned long>(
              kStage6DataModelPatchFinalResultProbeOffset),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(final_result),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x568)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x300)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x2f8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3b0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x3a8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5f8)),
          reinterpret_cast<void*>(static_cast<uintptr_t>(gregs[REG_R14])),
          IsReadableMemoryRange(rbp - 0x5c1, 1)
              ? *reinterpret_cast<const unsigned char*>(rbp - 0x5c1)
              : 0xffu);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++final_result_logs;
    }

    gregs[REG_RSI] = static_cast<greg_t>(final_result);
    gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6DataModelPatchFinalResultProbeOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6DataModelPatchTerminalFlagReadProbeOffset ||
      libroblox_offset ==
          kStage6DataModelPatchTerminalFlagReadProbeOffset + 1) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t flag_read_offset =
        kStage6DataModelPatchTerminalFlagReadProbeOffset;
    const uintptr_t flag_address =
        libroblox_base + kStage6ReThrowGetCachedPatchExceptionFlagOffset;
    const uintptr_t flag =
        IsReadableMemoryRange(flag_address, 1)
            ? *reinterpret_cast<const unsigned char*>(flag_address)
            : 0;
    const uintptr_t rax = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const uintptr_t result_pair = ReadPointerIfReadable(rbp - 0x570);
    const uintptr_t result_ref = ReadPointerIfReadable(rbp - 0x568);
    const uintptr_t loaded_patch = ReadPointerIfReadable(rbp - 0x548);
    const uintptr_t loaded_patch_ref = ReadPointerIfReadable(rbp - 0x540);
    const uintptr_t config_slot = ReadPointerIfReadable(rbp - 0x5d0);
    const uintptr_t config = ReadPointerIfReadable(config_slot);
    const uintptr_t provider = ReadPointerIfReadable(rbp - 0x5d8);
    const uintptr_t configurer = ReadPointerIfReadable(rbp - 0x5c0);

    static volatile sig_atomic_t terminal_logs = 0;
    if (terminal_logs < 16) {
      char msg[1800];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch terminal "
          "off=0x%lx flag=0x%lx rax_before=0x%lx rbp=%p "
          "result_pair=%p result_ref=%p loaded_patch=%p loaded_patch_ref=%p "
          "config_slot=%p config=%p provider=%p configurer=%p "
          "loop_state{5f8=%p 5e8=%p 5c1=0x%x 40=0x%lx} "
          "config_words{%p,%p,%p,%p}\n",
          static_cast<unsigned long>(flag_read_offset),
          static_cast<unsigned long>(flag), static_cast<unsigned long>(rax),
          reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(result_pair),
          reinterpret_cast<void*>(result_ref),
          reinterpret_cast<void*>(loaded_patch),
          reinterpret_cast<void*>(loaded_patch_ref),
          reinterpret_cast<void*>(config_slot), reinterpret_cast<void*>(config),
          reinterpret_cast<void*>(provider),
          reinterpret_cast<void*>(configurer),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5f8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5e8)),
          IsReadableMemoryRange(rbp - 0x5c1, 1)
              ? *reinterpret_cast<const unsigned char*>(rbp - 0x5c1)
              : 0xffu,
          static_cast<unsigned long>(ReadPointerIfReadable(configurer + 0x40)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x18)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++terminal_logs;
    }

    gregs[REG_RAX] = static_cast<greg_t>((rax & ~0xffULL) | flag);
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + flag_read_offset + 6);
    return true;
  }

  constexpr uintptr_t data_model_patch_helper_return_sites[] = {
      kStage6DataModelPatchHelperInitialReturnProbeOffset,
      kStage6DataModelPatchHelperConfigReturnProbeOffset,
      kStage6DataModelPatchHelperProviderReturnProbeOffset,
      kStage6DataModelPatchHelperReturnProbeOffset,
  };
  uintptr_t probe_offset = 0;
  for (uintptr_t candidate : data_model_patch_helper_return_sites) {
    if (libroblox_offset == candidate || libroblox_offset == candidate + 1) {
      probe_offset = candidate;
      break;
    }
  }
  if (probe_offset != 0) {
    auto* gregs = ucontext->uc_mcontext.gregs;
    const uintptr_t status = static_cast<uintptr_t>(gregs[REG_RAX]);
    const uintptr_t rbp = static_cast<uintptr_t>(gregs[REG_RBP]);
    const char* site_name = "final";
    uintptr_t local_patch_offset = 0x5b0;
    uintptr_t local_patch_ref_offset = 0x5a8;
    if (probe_offset == kStage6DataModelPatchHelperInitialReturnProbeOffset) {
      site_name = "initial";
      local_patch_offset = 0x540;
      local_patch_ref_offset = 0x538;
    } else if (probe_offset ==
               kStage6DataModelPatchHelperConfigReturnProbeOffset) {
      site_name = "config";
      local_patch_offset = 0x560;
      local_patch_ref_offset = 0x558;
    } else if (probe_offset ==
               kStage6DataModelPatchHelperProviderReturnProbeOffset) {
      site_name = "provider";
      local_patch_offset = 0x500;
      local_patch_ref_offset = 0x4f8;
    }

    const uintptr_t config_slot = ReadPointerIfReadable(rbp - 0x5d0);
    const uintptr_t config = ReadPointerIfReadable(config_slot);
    const uintptr_t content_config = ReadPointerIfReadable(rbp - 0x580);
    const uintptr_t provider = ReadPointerIfReadable(rbp - 0x5d8);
    const uintptr_t configurer = ReadPointerIfReadable(rbp - 0x5c0);
    const uintptr_t local_patch =
        ReadPointerIfReadable(rbp - local_patch_offset);
    const uintptr_t local_patch_ref =
        ReadPointerIfReadable(rbp - local_patch_ref_offset);
    const uintptr_t configurer_18 = ReadPointerIfReadable(configurer + 0x18);
    const uintptr_t configurer_20 = ReadPointerIfReadable(configurer + 0x20);
    char cfg00[96];
    char cfg08[96];
    char cfg08_ptr[96];
    char cfg10[96];
    char cfg10_ptr[96];
    char cfg18[96];
    char cfg30[96];
    char cfg48[96];
    char cfg60[96];
    char cfg78[96];
    char content_cfg08[96];
    char content_cfg10[96];
    char content_cfg18[96];
    ReadLibcxxStringPreview(config + 0x00, cfg00, sizeof(cfg00));
    ReadLibcxxStringPreview(config + 0x08, cfg08, sizeof(cfg08));
    ReadLibcxxStringPreview(ReadPointerIfReadable(config + 0x08), cfg08_ptr,
                            sizeof(cfg08_ptr));
    ReadLibcxxStringPreview(config + 0x10, cfg10, sizeof(cfg10));
    ReadLibcxxStringPreview(ReadPointerIfReadable(config + 0x10), cfg10_ptr,
                            sizeof(cfg10_ptr));
    ReadLibcxxStringPreview(config + 0x18, cfg18, sizeof(cfg18));
    ReadLibcxxStringPreview(config + 0x30, cfg30, sizeof(cfg30));
    ReadLibcxxStringPreview(config + 0x48, cfg48, sizeof(cfg48));
    ReadLibcxxStringPreview(config + 0x60, cfg60, sizeof(cfg60));
    ReadLibcxxStringPreview(config + 0x78, cfg78, sizeof(cfg78));
    ReadLibcxxStringPreview(content_config + 0x08, content_cfg08,
                            sizeof(content_cfg08));
    ReadLibcxxStringPreview(content_config + 0x10, content_cfg10,
                            sizeof(content_cfg10));
    ReadLibcxxStringPreview(content_config + 0x18, content_cfg18,
                            sizeof(content_cfg18));

    static volatile sig_atomic_t data_model_patch_helper_logs = 0;
    if (data_model_patch_helper_logs < 32) {
      char msg[3600];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 DataModel patch helper return "
          "site=%s off=0x%lx status=0x%lx rbp=%p "
          "stack{5d8=%p 5d0=%p 5c0=%p 580=%p 528=%p} "
          "config_slot=%p config=%p content_config=%p provider=%p "
          "configurer=%p local_pair=0x%lx/0x%lx "
          "local_patch=%p local_patch_ref=%p "
          "configurer_fields{18=%p 20=%p 28=%p 30=%p 38=%p 40=%p} "
          "config_words{%p,%p,%p,%p,%p,%p,%p,%p} "
          "config_strings{00='%s' 08='%s' 08p='%s' 10='%s' 10p='%s' "
          "18='%s' 30='%s' 48='%s' 60='%s' 78='%s'} "
          "content_config_strings{08='%s' 10='%s' 18='%s'}\n",
          site_name, static_cast<unsigned long>(probe_offset),
          static_cast<unsigned long>(status), reinterpret_cast<void*>(rbp),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5d8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5d0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x5c0)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x580)),
          reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x528)),
          reinterpret_cast<void*>(config_slot), reinterpret_cast<void*>(config),
          reinterpret_cast<void*>(content_config),
          reinterpret_cast<void*>(provider),
          reinterpret_cast<void*>(configurer),
          static_cast<unsigned long>(local_patch_offset),
          static_cast<unsigned long>(local_patch_ref_offset),
          reinterpret_cast<void*>(local_patch),
          reinterpret_cast<void*>(local_patch_ref),
          reinterpret_cast<void*>(configurer_18),
          reinterpret_cast<void*>(configurer_20),
          reinterpret_cast<void*>(ReadPointerIfReadable(configurer + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(configurer + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(configurer + 0x38)),
          reinterpret_cast<void*>(ReadPointerIfReadable(configurer + 0x40)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(config + 0x38)), cfg00,
          cfg08, cfg08_ptr, cfg10, cfg10_ptr, cfg18, cfg30, cfg48, cfg60, cfg78,
          content_cfg08, content_cfg10, content_cfg18);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++data_model_patch_helper_logs;
    }

    gregs[REG_RBX] = static_cast<greg_t>(status);
    gregs[REG_RIP] = static_cast<greg_t>(libroblox_base + probe_offset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartAppInstanceArgProbeOffset ||
      libroblox_offset == kStage6StartAppInstanceArgProbeOffset + 1) {
    const uintptr_t callback =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t vtable = ReadPointerIfReadable(callback);
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t fallback =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t variant = rbp >= 0x78 ? rbp - 0x78 : 0;
    const uintptr_t parent_return = ReadPointerIfReadable(rbp + 0x08);
    const uintptr_t parent_offset =
        parent_return >= libroblox_base ? parent_return - libroblox_base : 0;
    static volatile sig_atomic_t cast_logs = 0;
    if (cast_logs < 32) {
      char msg[1560];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartApp instance-arg cast "
          "off=0x%lx callback=%p vtable=%p output=%p fallback=%p "
          "parent_return=%p/off=0x%lx "
          "callback_fields{8=%p 10=%p 18=%p 20=%p 28=%p 30=%p 38=%p} "
          "vtable_slots{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p} "
          "variant=%p variant_fields{%p,%p,%p,%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(callback), reinterpret_cast<void*>(vtable),
          reinterpret_cast<void*>(output), reinterpret_cast<void*>(fallback),
          reinterpret_cast<void*>(parent_return),
          static_cast<unsigned long>(parent_offset),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(callback + 0x38)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(vtable + 0x30)),
          reinterpret_cast<void*>(variant),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x38)),
          reinterpret_cast<void*>(ReadPointerIfReadable(variant + 0x48)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++cast_logs;
    }
    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(vtable);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppInstanceArgProbeOffset + 3);
    return true;
  }

  auto multiply_request = [](uintptr_t value, uintptr_t factor) -> uintptr_t {
    if (factor != 0 && value > ~static_cast<uintptr_t>(0) / factor) {
      return ~static_cast<uintptr_t>(0);
    }
    return value * factor;
  };
  if ((libroblox_offset ==
           kStage6StartAppParamsVectorBackingAllocReturnOffset ||
       libroblox_offset ==
           kStage6StartAppParamsVectorBackingAllocReturnOffset + 1)) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t requested_count = ReadPointerIfReadable(rbp - 0x270);
    const uintptr_t requested_bytes = multiply_request(requested_count, 8);
    uintptr_t allocation =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    bool used_fallback = false;
    if (allocation == 0 && requested_bytes > 0 &&
        requested_bytes <=
            sizeof(g_stage6_start_app_params_vector_backing_scratch) &&
        !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_APP_PARAMS_ALLOC_FALLBACK")) {
      std::memset(g_stage6_start_app_params_vector_backing_scratch, 0,
                  static_cast<size_t>(requested_bytes));
      allocation = reinterpret_cast<uintptr_t>(
          g_stage6_start_app_params_vector_backing_scratch);
      used_fallback = true;
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(allocation);
    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(allocation);

    static volatile sig_atomic_t vector_backing_logs = 0;
    if (vector_backing_logs < 64) {
      const uintptr_t object =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
      char msg[780];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp params vector backing allocation fallback "
          "off=0x%lx object=%p allocation=%p requested_count=0x%lx "
          "requested=0x%lx fallback=%d\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(object), reinterpret_cast<void*>(allocation),
          static_cast<unsigned long>(requested_count),
          static_cast<unsigned long>(requested_bytes), used_fallback ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++vector_backing_logs;
    }

    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartAppParamsVectorBackingAllocReturnOffset +
        3);
    return true;
  }
  auto handle_start_app_params_alloc_return =
      [&](uintptr_t offset, int allocation_reg, unsigned char* scratch,
          size_t scratch_size, uintptr_t requested_bytes,
          const char* field_name) -> bool {
    if (libroblox_offset != offset && libroblox_offset != offset + 1) {
      return false;
    }

    uintptr_t allocation =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    bool used_fallback = false;
    if (allocation == 0 && requested_bytes > 0 &&
        requested_bytes <= scratch_size &&
        !IsDisabled("MOCKTAIL_PATCH_STAGE6_START_APP_PARAMS_ALLOC_FALLBACK")) {
      std::memset(scratch, 0, static_cast<size_t>(requested_bytes));
      allocation = reinterpret_cast<uintptr_t>(scratch);
      used_fallback = true;
    }

    ucontext->uc_mcontext.gregs[allocation_reg] =
        static_cast<greg_t>(allocation);

    static volatile sig_atomic_t allocation_logs = 0;
    if (allocation_logs < 64) {
      const uintptr_t object =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
      char msg[720];
      int len = snprintf(
          msg, sizeof(msg),
          "  [patch] Stage6 StartApp params allocation fallback "
          "off=0x%lx field=%s object=%p allocation=%p requested=0x%lx "
          "fallback=%d\n",
          static_cast<unsigned long>(libroblox_offset), field_name,
          reinterpret_cast<void*>(object), reinterpret_cast<void*>(allocation),
          static_cast<unsigned long>(requested_bytes), used_fallback ? 1 : 0);
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++allocation_logs;
    }

    ucontext->uc_mcontext.gregs[REG_RIP] =
        static_cast<greg_t>(libroblox_base + offset + 3);
    return true;
  };
  if (handle_start_app_params_alloc_return(
          kStage6StartAppParamsField40AllocReturnOffset, REG_R13,
          g_stage6_start_app_params_field40_scratch,
          sizeof(g_stage6_start_app_params_field40_scratch),
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]),
          "field40")) {
    return true;
  }
  if (handle_start_app_params_alloc_return(
          kStage6StartAppParamsField60AllocReturnOffset, REG_R13,
          g_stage6_start_app_params_field60_scratch,
          sizeof(g_stage6_start_app_params_field60_scratch),
          multiply_request(
              static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R12]), 2),
          "field60")) {
    return true;
  }
  if (handle_start_app_params_alloc_return(
          kStage6StartAppParamsField0AllocReturnOffset, REG_R12,
          g_stage6_start_app_params_field0_scratch,
          sizeof(g_stage6_start_app_params_field0_scratch),
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]),
          "field0")) {
    return true;
  }
  if (handle_start_app_params_alloc_return(
          kStage6StartAppParamsField20AllocReturnOffset, REG_R15,
          g_stage6_start_app_params_field20_scratch,
          sizeof(g_stage6_start_app_params_field20_scratch),
          multiply_request(
              static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]),
              0x10),
          "field20")) {
    return true;
  }

  if (libroblox_offset == kStage6AppBridgeV2OwnerInitHelperOffset ||
      libroblox_offset == kStage6AppBridgeV2OwnerInitHelperOffset + 1) {
    const uintptr_t receiver =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t owner = ReadPointerIfReadable(receiver + 0x20);
    const uintptr_t params_a =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t params_b =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    char msg[1180];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] AppBridge V2 owner-init helper entry off=0x%lx "
        "receiver=%p owner=%p args{rsi=%p rdx=%p rcx=%p r8=%p r9=%p} "
        "owner_slots{28=%p 30=%p 38=%p 118=%p 248=%p 3f8=%p 400=%p "
        "408=%p 410=%p 418=%p 420=%p 438=%p 448=%p 458=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(receiver), reinterpret_cast<void*>(owner),
        reinterpret_cast<void*>(params_a), reinterpret_cast<void*>(params_b),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9]),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x38)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x118)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x248)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x3f8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x400)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x408)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x410)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x418)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x420)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x438)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x448)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x458)));
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
          libroblox_base + kStage6AppBridgeV2OwnerInitHelperOffset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6AppBridgeV2OwnerStateStoreOffset ||
      libroblox_offset == kStage6AppBridgeV2OwnerStateStoreOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t slot = owner + 0x418;
    const uintptr_t old_state = ReadPointerIfReadable(slot);
    bool stored = false;
    if (owner >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(slot, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(slot) = state;
      stored = true;
    }
    if (stored && state >= kStage5LowAddressThreshold) {
      g_stage6_last_app_bridge_owner = owner;
      g_stage6_last_app_bridge_owner_state = state;
    }

    char msg[1020];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [trace] AppBridge V2 owner state-store off=0x%lx "
                 "owner=%p state=%p old_state=%p stored=%d "
                 "slots{3f8=%p 400=%p 408=%p 410=%p 418=%p 420=%p 438=%p "
                 "448=%p 458=%p} "
                 "state_fields{0=%p 8=%p 10=%p 18=%p 20=%p}\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(owner), reinterpret_cast<void*>(state),
                 reinterpret_cast<void*>(old_state), stored ? 1 : 0,
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x3f8)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x400)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x408)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x410)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x418)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x420)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x438)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x448)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x458)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x00)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x08)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x10)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x18)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6AppBridgeV2OwnerStateStoreOffset + 7);
    return true;
  }

  if (libroblox_offset == kNativeUpdateScreenOrientationCallbackSetupOffset ||
      libroblox_offset ==
          kNativeUpdateScreenOrientationCallbackSetupOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t state_slot = owner + 0x418;
    const uintptr_t old_state = ReadPointerIfReadable(state_slot);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] nativeUpdateScreenOrientation callback setup off=0x%lx "
        "owner=%p state_slot=%p old_state=%p byte620=0x%x "
        "r14=%p r15=%p primary=%p primary_fields{8=%p 10=%p 18=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(state_slot),
        reinterpret_cast<void*>(old_state),
        IsReadableMemoryRange(owner + 0x620, sizeof(unsigned char))
            ? static_cast<unsigned int>(
                  *reinterpret_cast<const unsigned char*>(owner + 0x620))
            : 0xffu,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
        reinterpret_cast<void*>(libroblox_base +
                                kStage6AppBridgePrimaryStateOffset),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6AppBridgePrimaryStateOffset + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6AppBridgePrimaryStateOffset + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6AppBridgePrimaryStateOffset + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ucontext->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(state_slot);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kNativeUpdateScreenOrientationCallbackSetupOffset + 7);
    return true;
  }

  if (libroblox_offset == kNativeUpdateScreenOrientationStateSlotLoadOffset ||
      libroblox_offset ==
          kNativeUpdateScreenOrientationStateSlotLoadOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t callback_node =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
    const uintptr_t state = ReadPointerIfReadable(owner + 0x418);
    char msg[840];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] nativeUpdateScreenOrientation registering callback "
        "off=0x%lx owner=%p state=%p callback=%p "
        "callback_fields{0=%p 8=%p 18=%p 20=%p 28=%p 30=%p 40=%p 48=%p "
        "50=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(state),
        reinterpret_cast<void*>(callback_node),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x40)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x48)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_node + 0x50)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(state);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kNativeUpdateScreenOrientationStateSlotLoadOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6EnableDmNotificationMonitorBlockOffset ||
      libroblox_offset == kStage6EnableDmNotificationMonitorBlockOffset + 1) {
    const uintptr_t flag_address =
        libroblox_base + kStage6EnableDmNotificationMonitorFlagOffset;
    unsigned char flag_value = 0;
    if (IsReadableMemoryRange(flag_address, sizeof(flag_value))) {
      flag_value = *reinterpret_cast<const unsigned char*>(flag_address);
    }
    const uintptr_t primary =
        libroblox_base + kStage6AppBridgePrimaryStateOffset;
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] reached EnableDMNotificationMonitor block off=0x%lx "
        "flag=0x%x rbx=%p r15=%p primary=%p primary_2c0=%p\n",
        static_cast<unsigned long>(libroblox_offset), flag_value,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15]),
        reinterpret_cast<void*>(primary),
        reinterpret_cast<void*>(ReadPointerIfReadable(primary + 0x2c0)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    greg_t rax = ucontext->uc_mcontext.gregs[REG_RAX];
    rax = (rax & ~static_cast<greg_t>(0xff)) | static_cast<greg_t>(flag_value);
    ucontext->uc_mcontext.gregs[REG_RAX] = rax;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6EnableDmNotificationMonitorBlockOffset + 6);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaAppDMGlobalLoadOffset ||
      libroblox_offset == kStage6StartLuaAppDMGlobalLoadOffset + 1) {
    const uintptr_t global_address =
        libroblox_base + kStage6StartLuaAppDMGlobalOffset;
    const uintptr_t global = ReadPointerIfReadable(global_address);
    const bool seeded0 = SeedStage6StartLuaTargetTableFallback(global, 0);
    const bool seeded1 = SeedStage6StartLuaTargetTableFallback(global, 1);
    char msg[1180];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM global load off=0x%lx "
        "global_addr=%p global=%p seeded{%d,%d} "
        "global_fields{0=%p 8=%p 10=%p 18=%p 1a0=%p "
        "850=%p 858=%p 860=%p 868=%p} "
        "main_thread_global=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(global_address),
        reinterpret_cast<void*>(global), seeded0 ? 1 : 0, seeded1 ? 1 : 0,
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x850)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x858)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x860)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x868)),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6StartLuaDMMainThreadIdGlobalOffset)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(global);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaAppDMGlobalLoadOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaAppDMBeforeDispatchOffset ||
      libroblox_offset == kStage6StartLuaAppDMBeforeDispatchOffset + 1) {
    const uintptr_t global =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    char msg[900];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM before dispatch off=0x%lx "
        "global=%p output=%p output_fields{%p,%p,%p,%p,%p} "
        "global_fields{%p,%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(global), reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaAppDMBeforeDispatchOffset + 2);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaAppDMAfterDispatchOffset ||
      libroblox_offset == kStage6StartLuaAppDMAfterDispatchOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t output = rbp >= 0x60 ? rbp - 0x60 : 0;
    const uintptr_t result = ReadPointerIfReadable(rbp - 0x40);
    char msg[920];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [trace] Stage6 StartLuaAppDM after dispatch off=0x%lx "
                 "output=%p output_fields{%p,%p,%p,%p,%p} "
                 "result=%p result_fields{%p,%p,%p,%p}\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(output),
                 reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x00)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x08)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x10)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x18)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x20)),
                 reinterpret_cast<void*>(result),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x00)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x08)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x10)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaAppDMAfterDispatchOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDMDispatchOffset ||
      libroblox_offset == kStage6StartLuaDMDispatchOffset + 1 ||
      libroblox_offset == kStage6StartLuaDMInvokerOffset ||
      libroblox_offset == kStage6StartLuaDMInvokerOffset + 1) {
    const bool is_dispatch =
        libroblox_offset == kStage6StartLuaDMDispatchOffset ||
        libroblox_offset == kStage6StartLuaDMDispatchOffset + 1;
    const uintptr_t function_offset = is_dispatch
                                          ? kStage6StartLuaDMDispatchOffset
                                          : kStage6StartLuaDMInvokerOffset;
    const uintptr_t arg0 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t arg1 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t arg2 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    char msg[1040];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] entered Stage6 StartLuaAppDM %s off=0x%lx "
        "arg0=%p arg1=%p arg2=%p "
        "arg0_fields{%p,%p,%p,%p,%p} arg1_fields{%p,%p,%p,%p,%p} "
        "main_thread_global=%p\n",
        is_dispatch ? "dispatch helper" : "invoker",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(arg0), reinterpret_cast<void*>(arg1),
        reinterpret_cast<void*>(arg2),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6StartLuaDMMainThreadIdGlobalOffset)));
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
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(libroblox_base + function_offset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6StartLuaDMDispatchSelectedManagerOffset ||
      libroblox_offset == kStage6StartLuaDMDispatchSelectedManagerOffset + 1) {
    const uintptr_t table =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t index =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) & 0xffu;
    const uintptr_t selected = ReadPointerIfReadable(table + index * 8);
    char msg[860];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM selected manager off=0x%lx "
        "table=%p index=0x%lx selected=%p "
        "table_entries{%p,%p} selected_fields{%p,%p,%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(table), static_cast<unsigned long>(index),
        reinterpret_cast<void*>(selected),
        reinterpret_cast<void*>(ReadPointerIfReadable(table + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(table + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(selected + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(selected);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDMDispatchSelectedManagerOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDMInvokerSameThreadObjectLoadOffset ||
      libroblox_offset ==
          kStage6StartLuaDMInvokerSameThreadObjectLoadOffset + 1) {
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t current_thread =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t main_thread =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t object = ReadPointerIfReadable(output + 0x20);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM invoker same-thread path off=0x%lx "
        "current_thread=%p main_thread=%p output=%p object=%p "
        "output_fields{%p,%p,%p,%p,%p} "
        "object_fields{%p,%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(current_thread),
        reinterpret_cast<void*>(main_thread), reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(object),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(object);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDMInvokerSameThreadObjectLoadOffset +
        4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDMInvokerAsyncPathOffset ||
      libroblox_offset == kStage6StartLuaDMInvokerAsyncPathOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t current_thread =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t main_thread =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t async_local = rbp >= 0x40 ? rbp - 0x40 : 0;
    const bool force_same_thread =
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD") &&
        (g_start_lua_app_dm_recovery_in_progress != kStage6RecoveryInactive ||
         IsEnabled(
             "MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD_GLOBAL"));
    char msg[820];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM invoker async path off=0x%lx "
        "current_thread=%p main_thread=%p output=%p async_local=%p "
        "output_fields{%p,%p,%p,%p,%p} main_thread_global=%p "
        "force_same_thread=%d\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(current_thread),
        reinterpret_cast<void*>(main_thread), reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(async_local),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(output + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(
            libroblox_base + kStage6StartLuaDMMainThreadIdGlobalOffset)),
        force_same_thread ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (force_same_thread) {
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaDMInvokerSameThreadObjectLoadOffset);
      return true;
    }

    ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(async_local);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDMInvokerAsyncPathOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDMInvokerNullResultOffset ||
      libroblox_offset == kStage6StartLuaDMInvokerNullResultOffset + 1) {
    const uintptr_t error_object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    char msg[560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLuaAppDM invoker null-result path off=0x%lx "
        "error_object=%p fields{%p,%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(error_object),
        reinterpret_cast<void*>(ReadPointerIfReadable(error_object + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(error_object + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(error_object + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(error_object + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(error_object);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDMInvokerNullResultOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaSingleSurfaceStartLuaAppOffset ||
      libroblox_offset == kStage6StartLuaSingleSurfaceStartLuaAppOffset + 1 ||
      libroblox_offset == kStage6StartLuaUserDidLoginOffset ||
      libroblox_offset == kStage6StartLuaUserDidLoginOffset + 1 ||
      libroblox_offset == kStage6StartLuaDeepStartOffset ||
      libroblox_offset == kStage6StartLuaDeepStartOffset + 1 ||
      libroblox_offset == kStage6StartLuaDeepAppStateUpdateOffset ||
      libroblox_offset == kStage6StartLuaDeepAppStateUpdateOffset + 1 ||
      libroblox_offset == kStage6StartLuaDeepStateCopyOffset ||
      libroblox_offset == kStage6StartLuaDeepStateCopyOffset + 1) {
    const bool is_start_lua_app =
        libroblox_offset == kStage6StartLuaSingleSurfaceStartLuaAppOffset ||
        libroblox_offset == kStage6StartLuaSingleSurfaceStartLuaAppOffset + 1;
    const bool is_user_did_login =
        libroblox_offset == kStage6StartLuaUserDidLoginOffset ||
        libroblox_offset == kStage6StartLuaUserDidLoginOffset + 1;
    const bool is_deep = libroblox_offset == kStage6StartLuaDeepStartOffset ||
                         libroblox_offset == kStage6StartLuaDeepStartOffset + 1;
    const bool is_app_state_update =
        libroblox_offset == kStage6StartLuaDeepAppStateUpdateOffset ||
        libroblox_offset == kStage6StartLuaDeepAppStateUpdateOffset + 1;
    const uintptr_t function_offset =
        is_start_lua_app
            ? kStage6StartLuaSingleSurfaceStartLuaAppOffset
            : (is_user_did_login
                   ? kStage6StartLuaUserDidLoginOffset
                   : (is_deep ? kStage6StartLuaDeepStartOffset
                              : (is_app_state_update
                                     ? kStage6StartLuaDeepAppStateUpdateOffset
                                     : kStage6StartLuaDeepStateCopyOffset)));
    const uintptr_t arg0 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t arg1 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t arg2 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);

    char msg[1240];
    int len = 0;
    if (is_start_lua_app) {
      uint32_t stage = 0xffffffffu;
      if (IsReadableMemoryRange(arg0 + 0x2b0, sizeof(stage))) {
        stage = *reinterpret_cast<const uint32_t*>(arg0 + 0x2b0);
      }
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 single-surface startLuaApp off=0x%lx "
          "app=%p params=%p stage=0x%x "
          "app_slots{3f8=%p 418=%p 438=%p 448=%p 458=%p 468=%p 478=%p} "
          "params{%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(arg0), reinterpret_cast<void*>(arg1), stage,
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x3f8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x418)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x438)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x448)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x458)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x468)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x478)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x20)));
    } else if (is_user_did_login) {
      const uintptr_t owner = ReadPointerIfReadable(arg0 + 0x20);
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 userDidLogin off=0x%lx "
          "receiver=%p owner=%p payload=%p arg2=%p "
          "owner_slots{118=%p 3f8=%p 418=%p 850=%p 858=%p 860=%p 868=%p} "
          "payload{%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(arg0), reinterpret_cast<void*>(owner),
          reinterpret_cast<void*>(arg1), reinterpret_cast<void*>(arg2),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x118)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x3f8)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x418)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x850)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x858)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x860)),
          reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x868)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x20)));
    } else if (is_deep) {
      uint32_t phase = 0xffffffffu;
      if (IsReadableMemoryRange(arg0 + 0x138, sizeof(phase))) {
        phase = *reinterpret_cast<const uint32_t*>(arg0 + 0x138);
      }
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 deep StartLua off=0x%lx "
          "state=%p phase=0x%x payload=%p "
          "state_fields{0=%p 8=%p 18=%p 100=%p 118=%p 140=%p} "
          "payload{%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(arg0), phase, reinterpret_cast<void*>(arg1),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x100)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x118)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x140)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x20)));
    } else if (is_app_state_update) {
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 deep app-state update off=0x%lx "
          "app_state=%p new_value=%p old_value=%p "
          "fields{0=%p 8=%p 18=%p 100=%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(arg0), reinterpret_cast<void*>(arg1),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x100)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg0 + 0x100)));
    } else {
      uint32_t phase = 0xffffffffu;
      if (IsReadableMemoryRange(arg0 + 0x138, sizeof(phase))) {
        phase = *reinterpret_cast<const uint32_t*>(arg0 + 0x138);
      }
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 deep state-copy off=0x%lx "
          "state=%p phase=0x%x payload_block=%p "
          "payload{%p,%p,%p,%p,%p,%p,%p}\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(arg0), phase, reinterpret_cast<void*>(arg1),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x30)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x68)),
          reinterpret_cast<void*>(ReadPointerIfReadable(arg1 + 0x90)));
    }
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (is_start_lua_app) {
      if (ReadPointerIfReadable(arg0 + 0x3f8) == 0) {
        InstallStage6StartLuaFallbackCallbackTarget(
            arg0, "single-surface-startLuaApp");
      }
      if (ReadPointerIfReadable(arg0 + 0x418) == 0) {
        InstallStage6StartLuaFallbackState(arg0, 0,
                                           "single-surface-startLuaApp");
      }
      SeedStage6StartLuaTargetTableFallback(arg0, 0);
      SeedStage6StartLuaTargetTableFallback(arg0, 1);
      SeedStage6StartLuaPrimaryStateFromOwner(arg0,
                                              "single-surface-startLuaApp");
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
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(libroblox_base + function_offset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6StartLuaUserDidLoginDeepCallStateLoadOffset ||
      libroblox_offset ==
          kStage6StartLuaUserDidLoginDeepCallStateLoadOffset + 1) {
    const uintptr_t owner =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    uintptr_t state = ReadPointerIfReadable(owner + 0x418);
    if (state == 0) {
      state = InstallStage6StartLuaFallbackState(owner, 0,
                                                 "userDidLogin-deep-call");
    }
    SeedStage6StartLuaGatePayload(payload, "userDidLogin-deep-call");
    uint32_t phase = 0xffffffffu;
    if (IsReadableMemoryRange(state + 0x138, sizeof(phase))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    char msg[960];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 userDidLogin before deep call off=0x%lx "
        "owner=%p state=%p phase=0x%x payload=%p "
        "owner_slots{118=%p 3f8=%p 418=%p} "
        "payload{%p,%p,%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(owner), reinterpret_cast<void*>(state), phase,
        reinterpret_cast<void*>(payload),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x118)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x3f8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x418)),
        reinterpret_cast<void*>(ReadPointerIfReadable(payload + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(payload + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(payload + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(payload + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(payload + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(state);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaUserDidLoginDeepCallStateLoadOffset +
        7);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDeepHeaderLoadOffset ||
      libroblox_offset == kStage6StartLuaDeepHeaderLoadOffset + 1) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    uintptr_t header = ReadPointerIfReadable(state + 0x00);
    if ((header == 0 || ReadPointerIfReadable(header + 0x08) == 0) &&
        SeedStage6StartLuaDeepStateHeader(state, "deep-header-load")) {
      header = ReadPointerIfReadable(state + 0x00);
    }
    uint32_t phase = 0xffffffffu;
    if (IsReadableMemoryRange(state + 0x138, sizeof(phase))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    char msg[860];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 deep header load off=0x%lx "
        "state=%p phase=0x%x header=%p "
        "header_fields{0=%p 8=%p 10=%p 18=%p} "
        "state_slots{100=%p 118=%p 140=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(state), phase, reinterpret_cast<void*>(header),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x100)),
        reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x118)),
        reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x140)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(header);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDeepHeaderLoadOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDeepHeaderChecksPassedOffset ||
      libroblox_offset == kStage6StartLuaDeepHeaderChecksPassedOffset + 1) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t header = ReadPointerIfReadable(state + 0x00);
    char msg[700];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 deep header checks passed off=0x%lx "
        "state=%p header=%p header8=%p state138=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(state), reinterpret_cast<void*>(header),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x08)),
        reinterpret_cast<void*>(state + 0x138));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_R13] = static_cast<greg_t>(state + 0x138);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDeepHeaderChecksPassedOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDeepCleanupOffset ||
      libroblox_offset == kStage6StartLuaDeepCleanupOffset + 1) {
    const uintptr_t scratch =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t header = ReadPointerIfReadable(state + 0x00);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 deep cleanup path off=0x%lx "
        "scratch=%p scratch_fields{%p,%p,%p} state=%p header=%p header8=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(scratch),
        reinterpret_cast<void*>(ReadPointerIfReadable(scratch + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(scratch + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(scratch + 0x10)),
        reinterpret_cast<void*>(state), reinterpret_cast<void*>(header),
        reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x08)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(scratch);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDeepCleanupOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaGateStateLoadOffset ||
      libroblox_offset == kStage6StartLuaGateStateLoadOffset + 1) {
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
    SeedStage6StartLuaGatePayload(payload, "gate-state-load");
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
    return true;
  }

  if (libroblox_offset == kStage6StartLuaGateDeepArgsOffset ||
      libroblox_offset == kStage6StartLuaGateDeepArgsOffset + 1) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    uint32_t phase = 0xffffffffu;
    uint64_t payload_first = 0;
    if (IsReadableMemoryRange(state + 0x138, sizeof(uint32_t))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    if (IsReadableMemoryRange(payload, sizeof(uint64_t))) {
      payload_first = *reinterpret_cast<const uint64_t*>(payload);
    }

    char msg[560];
    int len = snprintf(msg, sizeof(msg),
                       "  [trace] Stage6 StartLua gate passed branch off=0x%lx "
                       "state=%p phase=0x%x payload=%p payload0=0x%llx\n",
                       static_cast<unsigned long>(libroblox_offset),
                       reinterpret_cast<void*>(state), phase,
                       reinterpret_cast<void*>(payload),
                       static_cast<unsigned long long>(payload_first));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = ucontext->uc_mcontext.gregs[REG_R14];
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaGateDeepArgsOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaGateReturnOffset ||
      libroblox_offset == kStage6StartLuaGateReturnOffset + 1) {
    const uintptr_t state =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t payload =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    uint32_t phase = 0xffffffffu;
    uint64_t payload_first = 0;
    if (IsReadableMemoryRange(state + 0x138, sizeof(uint32_t))) {
      phase = *reinterpret_cast<const uint32_t*>(state + 0x138);
    }
    if (IsReadableMemoryRange(payload, sizeof(uint64_t))) {
      payload_first = *reinterpret_cast<const uint64_t*>(payload);
    }

    char msg[560];
    int len = snprintf(msg, sizeof(msg),
                       "  [trace] Stage6 StartLua gate return path off=0x%lx "
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
    if (IsReadableMemoryRange(rsp, sizeof(uintptr_t))) {
      ucontext->uc_mcontext.gregs[REG_RBX] =
          static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rsp));
      ucontext->uc_mcontext.gregs[REG_RSP] =
          static_cast<greg_t>(rsp + sizeof(uintptr_t));
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaGateReturnOffset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6StartLuaLoggedInTargetEntryOffset ||
      libroblox_offset == kStage6StartLuaLoggedInTargetEntryOffset + 1) {
    const uintptr_t boxed_lookup_flag_address =
        libroblox_base + kStage6StartLuaLoggedInTargetBoxedLookupFlagOffset;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_BOXED_TARGET_LOOKUP") &&
        EnsureWritablePage(
            reinterpret_cast<void*>(boxed_lookup_flag_address))) {
      *reinterpret_cast<unsigned char*>(boxed_lookup_flag_address) = 1;
    }
    unsigned char boxed_lookup_flag = 0;
    if (IsReadableMemoryRange(boxed_lookup_flag_address,
                              sizeof(boxed_lookup_flag))) {
      boxed_lookup_flag =
          *reinterpret_cast<const unsigned char*>(boxed_lookup_flag_address);
    }
    const uintptr_t object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t output =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uint32_t index =
        static_cast<uint32_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    uint32_t active_slot = 0xffffffffu;
    if (IsReadableMemoryRange(object + 0x7d8, sizeof(active_slot))) {
      active_slot = *reinterpret_cast<const uint32_t*>(object + 0x7d8);
    }
    SeedStage6StartLuaTargetTableFallback(object, index);
    LogStage6StartLuaTargetCandidates(object);

    char msg[980];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] entered Stage6 logged-in target helper off=0x%lx "
        "object=%p index=%u boxed_lookup=0x%x active_slot=0x%x output=%p "
        "table0{%p,%p} table1{%p,%p} fields{0=%p 8=%p 10=%p 18=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(object), index, boxed_lookup_flag, active_slot,
        reinterpret_cast<void*>(output),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x850)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x858)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x860)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x868)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x18)));
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
          libroblox_base + kStage6StartLuaLoggedInTargetEntryOffset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6StartLuaTargetApplyOffset ||
      libroblox_offset == kStage6StartLuaTargetApplyOffset + 1 ||
      libroblox_offset == kStage6StartLuaTargetPostApplyOffset ||
      libroblox_offset == kStage6StartLuaTargetPostApplyOffset + 1) {
    const bool is_apply =
        libroblox_offset == kStage6StartLuaTargetApplyOffset ||
        libroblox_offset == kStage6StartLuaTargetApplyOffset + 1;
    const uintptr_t function_offset =
        is_apply ? kStage6StartLuaTargetApplyOffset
                 : kStage6StartLuaTargetPostApplyOffset;
    const uintptr_t arg0 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t arg1 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t pair_base = is_apply ? arg1 : arg0;
    const uintptr_t target_object =
        is_apply && arg0 >= 0x1a0 ? arg0 - 0x1a0 : ReadPointerIfReadable(arg0);
    char msg[980];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] entered Stage6 StartLua target %s off=0x%lx "
        "arg0=%p arg1=%p pair=%p target_object=%p "
        "target_fields{0=%p 18=%p 20=%p 28=%p 1a0=%p 1b8=%p 1c0=%p} "
        "pair{%p,%p}\n",
        is_apply ? "apply" : "post-apply",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(arg0), reinterpret_cast<void*>(arg1),
        reinterpret_cast<void*>(pair_base),
        reinterpret_cast<void*>(target_object),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x1b8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_object + 0x1c0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair_base + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair_base + 0x08)));
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
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(libroblox_base + function_offset + 1);
      return true;
    }
  }

  if (libroblox_offset == kStage6StartLuaTargetPostApplyTriggerOffset ||
      libroblox_offset == kStage6StartLuaTargetPostApplyTriggerOffset + 1) {
    const uintptr_t pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t target = ReadPointerIfReadable(pair);
    const uintptr_t refcount = ReadPointerIfReadable(pair + 0x08);
    unsigned int flag = 0xffu;
    if (IsReadableMemoryRange(target + 0x158, sizeof(unsigned char))) {
      flag = *reinterpret_cast<const unsigned char*>(target + 0x158);
    }
    char msg[720];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua target post-apply trigger off=0x%lx "
        "pair=%p target=%p ref=%p target_flag158=0x%x old_cl=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(pair), reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(refcount), flag,
        static_cast<unsigned long>(ucontext->uc_mcontext.gregs[REG_RCX] &
                                   0xff));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyTaskThunkOffset);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyTriggerOffset + 7);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaTargetPostApplyCallbackOffset ||
      libroblox_offset == kStage6StartLuaTargetPostApplyCallbackOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t callback =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t callback_context = ReadPointerIfReadable(rbp - 0xb8);
    const bool force_pair_argument =
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_POST_APPLY_PAIR_ARGUMENT");
    const bool force_null_argument =
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_POST_APPLY_NULL_ARGUMENT");
    char msg[820];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua target post-apply callback off=0x%lx "
        "pair=%p target=%p ref=%p callback=%p context=%p "
        "force_pair_argument=%d force_null_argument=%d\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(pair),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair)),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x08)),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_context), force_pair_argument ? 1 : 0,
        force_null_argument ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] =
        static_cast<greg_t>(callback_context);
    if (force_pair_argument) {
      ucontext->uc_mcontext.gregs[REG_RSI] = static_cast<greg_t>(pair);
    } else if (force_null_argument) {
      ucontext->uc_mcontext.gregs[REG_RSI] = 0;
    }
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyCallbackOffset +
        (force_pair_argument || force_null_argument ? 10 : 7));
    return true;
  }

  if (libroblox_offset == kStage6StartLuaTargetPostApplyExitOffset ||
      libroblox_offset == kStage6StartLuaTargetPostApplyExitOffset + 1) {
    const uintptr_t pair =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t rsi =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t r15 =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
    const uintptr_t canary = ReadPointerIfReadable(r15);
    const uintptr_t target = ReadPointerIfReadable(pair);
    unsigned int flag = 0xffu;
    if (IsReadableMemoryRange(target + 0x158, sizeof(unsigned char))) {
      flag = *reinterpret_cast<const unsigned char*>(target + 0x158);
    }
    const uintptr_t target_d8 = ReadPointerIfReadable(target + 0xd8);
    char msg[1240];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua target post-apply exit off=0x%lx "
        "pair=%p rsi=%p target=%p ref=%p target_flag158=0x%x "
        "target_slots{d8=%p e0=%p 1a0=%p 438=%p} "
        "target_d8_fields{%p,%p,%p} canary=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(pair), reinterpret_cast<void*>(rsi),
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x08)), flag,
        reinterpret_cast<void*>(target_d8),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0xe0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x438)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x10)),
        reinterpret_cast<void*>(canary));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(canary);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyExitOffset + 3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDispatcherEmptyInvokeOffset ||
      libroblox_offset == kStage6StartLuaDispatcherEmptyInvokeOffset + 1) {
    const uintptr_t function_object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t callback = ReadPointerIfReadable(function_object + 0x00);
    const uintptr_t callback_context =
        ReadPointerIfReadable(function_object + 0x08);
    const uintptr_t callback_pair =
        ReadPointerIfReadable(function_object + 0x10);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua dispatcher empty invoke off=0x%lx "
        "function_object=%p callback=%p context=%p pair=%p "
        "fields{%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(function_object),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_context),
        reinterpret_cast<void*>(callback_pair),
        reinterpret_cast<void*>(ReadPointerIfReadable(function_object + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(function_object + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(function_object + 0x10)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] =
        static_cast<greg_t>(callback_context);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDispatcherEmptyInvokeOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaDispatcherSecondInvokeOffset ||
      libroblox_offset == kStage6StartLuaDispatcherSecondInvokeOffset + 1) {
    const uintptr_t function_object =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R14]);
    const uintptr_t callback = ReadPointerIfReadable(function_object + 0x00);
    const uintptr_t callback_context =
        ReadPointerIfReadable(function_object + 0x08);
    const uintptr_t callback_pair =
        ReadPointerIfReadable(function_object + 0x10);
    const bool force_pair_argument =
        IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_DISPATCHER_SECOND_PAIR_"
            "ARGUMENT") &&
        callback_pair >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(callback_pair, 2 * sizeof(uintptr_t));
    char msg[860];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua dispatcher second invoke off=0x%lx "
        "function_object=%p callback=%p context=%p pair=%p "
        "force_pair_argument=%d pair_fields{%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(function_object),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_context),
        reinterpret_cast<void*>(callback_pair), force_pair_argument ? 1 : 0,
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_pair + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_pair + 0x08)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (force_pair_argument) {
      ucontext->uc_mcontext.gregs[REG_RDI] =
          static_cast<greg_t>(callback_context);
      ucontext->uc_mcontext.gregs[REG_RSI] = static_cast<greg_t>(callback_pair);
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base + kStage6StartLuaDispatcherSecondInvokeCallOffset);
      return true;
    }

    ucontext->uc_mcontext.gregs[REG_RDI] =
        static_cast<greg_t>(callback_context);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaDispatcherSecondInvokeOffset + 4);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaTargetPostApplyTaskThunkOffset ||
      libroblox_offset == kStage6StartLuaTargetPostApplyTaskThunkOffset + 1) {
    const uintptr_t context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t argument =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    const uintptr_t original_pair = ReadPointerIfReadable(context);
    const uintptr_t original_target = ReadPointerIfReadable(original_pair);
    const uintptr_t original_ref = ReadPointerIfReadable(original_pair + 0x08);
    char msg[1120];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk entry off=0x%lx "
        "context=%p argument=%p context_fields{%p,%p} "
        "pair=%p pair_fields{%p,%p} "
        "target_fields{0=%p 18=%p 20=%p 28=%p 158=%p 1a0=%p 1b8=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(context), reinterpret_cast<void*>(argument),
        reinterpret_cast<void*>(ReadPointerIfReadable(context + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(context + 0x08)),
        reinterpret_cast<void*>(original_pair),
        reinterpret_cast<void*>(original_target),
        reinterpret_cast<void*>(original_ref),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(original_target + 0x1a0)),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(original_target + 0x1b8)));
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
          libroblox_base + kStage6StartLuaTargetPostApplyTaskThunkOffset + 1);
      return true;
    }
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkInitReadyOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkInitReadyOffset + 1) {
    const uintptr_t global_string = ReadPointerIfReadable(
        libroblox_base + kStage6StartLuaTaskThunkGlobalStringPointerOffset);
    char msg[560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk init-ready "
        "off=0x%lx global_string=%p global_fields{%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(global_string),
        reinterpret_cast<void*>(ReadPointerIfReadable(global_string + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global_string + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(global_string + 0x10)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_R14] = static_cast<greg_t>(global_string);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkInitReadyOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkBeforeTargetCallOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkBeforeTargetCallOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t pair = ReadPointerIfReadable(context);
    const uintptr_t target = ReadPointerIfReadable(pair);
    const uintptr_t target_callback_object =
        InstallStage6StartLuaTargetCallbackObject(target, context,
                                                  "post-apply target-call");
    const uintptr_t target_vtable = ReadPointerIfReadable(target);
    const uintptr_t target_callback =
        ReadPointerIfReadable(target_vtable + 0x30);
    const uintptr_t target_field_438 = ReadPointerIfReadable(target + 0x438);
    char msg[1220];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk before target-call "
        "off=0x%lx context=%p pair=%p pair_fields{%p,%p} "
        "local_pair{%p,%p} target=%p vtable=%p vtable30=%p "
        "target438=%p installed_target438=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(context), reinterpret_cast<void*>(pair),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x150)),
        reinterpret_cast<void*>(ReadPointerIfReadable(rbp - 0x148)),
        reinterpret_cast<void*>(target), reinterpret_cast<void*>(target_vtable),
        reinterpret_cast<void*>(target_callback),
        reinterpret_cast<void*>(target_field_438),
        reinterpret_cast<void*>(target_callback_object));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] =
        static_cast<greg_t>(ReadPointerIfReadable(context));
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkBeforeTargetCallOffset + 3);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterTargetCallOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterTargetCallOffset + 1) {
    uintptr_t target_result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    const uintptr_t pair = ReadPointerIfReadable(context);
    const uintptr_t target = ReadPointerIfReadable(pair);
    uintptr_t patched_target_result = 0;
    if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALL_RESULT") &&
        !IsReadableMemoryRange(target_result, 0x30) &&
        target >= kStage5LowAddressThreshold) {
      const uintptr_t fallback_result = ReadPointerIfReadable(target + 0x1a0);
      if (fallback_result >= kStage5LowAddressThreshold &&
          IsReadableMemoryRange(fallback_result, 0x30)) {
        target_result = fallback_result;
        patched_target_result = fallback_result;
        ucontext->uc_mcontext.gregs[REG_RAX] =
            static_cast<greg_t>(target_result);
      }
    }
    const uintptr_t result20 = ReadPointerIfReadable(target_result + 0x20);
    const uintptr_t result20_callback = ReadPointerIfReadable(result20 + 0x08);
    const uintptr_t result20_source = ReadPointerIfReadable(result20 + 0x20);
    const uintptr_t result20_source_ref =
        ReadPointerIfReadable(result20 + 0x28);
    const uintptr_t resolve_global = ReadPointerIfReadable(
        libroblox_base + kStage6StartLuaTaskThunkResolveGlobalOffset);
    const bool force_result20_callback =
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_CALLBACK");
    const bool force_result20_pair_callback = IsEnabled(
        "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PAIR_CALLBACK");
    const bool force_split_callback_args = IsEnabled(
        "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_"
        "ARGS");
    const bool result20_callback_in_text =
        result20_callback >= libroblox_base + 0x1f235c0 &&
        result20_callback < libroblox_base + 0x6b22cea;
    uintptr_t result20_callback_arg =
        force_result20_pair_callback ? pair : result20;
    bool prefer_result20_pair_arg = false;
    if (force_result20_pair_callback &&
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PREFER_"
                  "RESULT_PAIR") &&
        pair >= kStage5LowAddressThreshold &&
        result20 >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(pair, 2 * sizeof(uintptr_t)) &&
        IsReadableMemoryRange(result20 + 0x10, 2 * sizeof(uintptr_t))) {
      const uintptr_t pair_ref = ReadPointerIfReadable(pair + 0x08);
      const uintptr_t result20_target = ReadPointerIfReadable(result20 + 0x10);
      const uintptr_t result20_ref = ReadPointerIfReadable(result20 + 0x18);
      if (pair_ref < kStage5LowAddressThreshold &&
          result20_target >= kStage5LowAddressThreshold &&
          result20_ref >= kStage5LowAddressThreshold) {
        result20_callback_arg = result20 + 0x10;
        prefer_result20_pair_arg = true;
      }
    }
    const uintptr_t owner_source_before = ReadPointerIfReadable(target + 0x228);
    bool seeded_owner_source = false;
    uintptr_t owner_source_candidate = 0;
    const char* owner_source_slot = std::getenv(
        "MOCKTAIL_STAGE6_START_LUA_OWNER_SOURCE_FROM_RESULT20_SLOT");
    if (owner_source_slot != nullptr && owner_source_slot[0] != '\0' &&
        target >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(target + 0x228, sizeof(uintptr_t)) &&
        owner_source_before < kStage5LowAddressThreshold) {
      if (std::strcmp(owner_source_slot, "28") == 0 ||
          std::strcmp(owner_source_slot, "0x28") == 0) {
        owner_source_candidate = result20_source_ref;
      } else {
        owner_source_candidate = result20_source;
      }
      if (owner_source_candidate >= kStage5LowAddressThreshold &&
          EnsureWritablePage(reinterpret_cast<void*>(target + 0x228))) {
        *reinterpret_cast<uintptr_t*>(target + 0x228) = owner_source_candidate;
        seeded_owner_source = true;
      }
    }
    char msg[1900];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk after target-call "
        "off=0x%lx context=%p pair=%p target=%p target_result=%p "
        "patched_target_result=%p result_fields{%p,%p,%p} "
        "result20_fields{%p,%p,%p,%p,%p,%p} "
        "resolve_global=%p result20_callback=%p "
        "result20_callback_arg=%p result20_callback_in_text=%d "
        "force_result20_callback=%d force_result20_pair_callback=%d "
        "force_split_callback_args=%d prefer_result20_pair_arg=%d "
        "owner228_before=%p owner_source_candidate=%p "
        "seeded_owner_source=%d\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(context), reinterpret_cast<void*>(pair),
        reinterpret_cast<void*>(target), reinterpret_cast<void*>(target_result),
        reinterpret_cast<void*>(patched_target_result),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_result + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x28)),
        reinterpret_cast<void*>(resolve_global),
        reinterpret_cast<void*>(result20_callback),
        reinterpret_cast<void*>(result20_callback_arg),
        result20_callback_in_text ? 1 : 0, force_result20_callback ? 1 : 0,
        force_result20_pair_callback ? 1 : 0, force_split_callback_args ? 1 : 0,
        prefer_result20_pair_arg ? 1 : 0,
        reinterpret_cast<void*>(owner_source_before),
        reinterpret_cast<void*>(owner_source_candidate),
        seeded_owner_source ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if ((force_result20_callback || force_result20_pair_callback) &&
        result20_callback_arg >= kStage5LowAddressThreshold &&
        result20_callback_in_text) {
      const uintptr_t rbp =
          static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
      if (rbp >= 0xd0 && IsReadableMemoryRange(rbp - 0xd0, 0x10) &&
          EnsureWritablePage(reinterpret_cast<void*>(rbp - 0xd0))) {
        uintptr_t split_context = 0;
        if (force_result20_pair_callback && force_split_callback_args) {
          split_context = PrepareStage6StartLuaResult20SplitCallbackContext(
              result20_callback, result20_callback_arg);
        }
        *reinterpret_cast<uintptr_t*>(rbp - 0xd0) = result20_callback;
        *reinterpret_cast<uintptr_t*>(rbp - 0xc8) = result20_callback_arg;
        char patch_msg[700];
        int patch_len = snprintf(
            patch_msg, sizeof(patch_msg),
            "  [patch] Stage6 StartLua resolver result20 callback materialized "
            "callback=%p arg=%p split_context=%p out_pair=%p\n",
            reinterpret_cast<void*>(result20_callback),
            reinterpret_cast<void*>(result20_callback_arg),
            reinterpret_cast<void*>(split_context),
            reinterpret_cast<void*>(rbp - 0xd0));
        if (patch_len > 0) {
          write(2, patch_msg, static_cast<size_t>(patch_len));
        }
        ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
            libroblox_base +
            kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset);
        return true;
      }
    }

    ucontext->uc_mcontext.gregs[REG_RCX] = static_cast<greg_t>(resolve_global);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkAfterTargetCallOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t callback = ReadPointerIfReadable(rbp - 0xd0);
    const uintptr_t callback_arg = ReadPointerIfReadable(rbp - 0xc8);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk after resolve "
        "off=0x%lx callback=%p callback_arg=%p "
        "callback_arg_fields{%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_arg),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(callback_arg + 0x10)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(callback);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkCallbackInvokeOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkCallbackInvokeOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t callback =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    const uintptr_t callback_arg = ReadPointerIfReadable(rbp - 0xc8);
    const bool split_args =
        IsEnabled(
            "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_"
            "ARGS") &&
        callback == g_stage6_start_lua_result20_callback_split_callback &&
        callback_arg ==
            g_stage6_start_lua_result20_callback_split_source_pair &&
        g_stage6_start_lua_result20_callback_split_context >=
            kStage5LowAddressThreshold &&
        IsReadableMemoryRange(
            g_stage6_start_lua_result20_callback_split_context,
            2 * sizeof(uintptr_t));
    char msg[780];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk callback invoke "
        "off=0x%lx callback=%p callback_arg=%p split_args=%d "
        "split_context=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_arg), split_args ? 1 : 0,
        reinterpret_cast<void*>(
            g_stage6_start_lua_result20_callback_split_context));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    if (split_args) {
      ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(
          g_stage6_start_lua_result20_callback_split_context);
      ucontext->uc_mcontext.gregs[REG_RSI] = static_cast<greg_t>(callback_arg);
      ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
          libroblox_base +
          kStage6StartLuaTargetPostApplyTaskThunkCallbackCallOffset);
      return true;
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(callback_arg);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkCallbackInvokeOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset + 1) {
    const uintptr_t rbp =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    const uintptr_t callback = ReadPointerIfReadable(rbp - 0xd0);
    const uintptr_t callback_arg = ReadPointerIfReadable(rbp - 0xc8);
    const uintptr_t local_target = ReadPointerIfReadable(rbp - 0x150);
    const uintptr_t local_ref = ReadPointerIfReadable(rbp - 0x148);
    const uintptr_t split_context =
        g_stage6_start_lua_result20_callback_split_context;
    const uintptr_t split_owner = ReadPointerIfReadable(split_context + 0x00);
    const uintptr_t split_control = ReadPointerIfReadable(split_context + 0x08);
    const uintptr_t target_d8 = ReadPointerIfReadable(local_target + 0xd8);
    const uintptr_t split_owner_d8 = ReadPointerIfReadable(split_owner + 0xd8);
    char msg[1780];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk after callback "
        "off=0x%lx callback=%p callback_arg=%p "
        "local_pair{%p,%p} split_context=%p "
        "split_context_fields{%p,%p} target_slots{d8=%p e0=%p 1a0=%p "
        "1c8=%p 228=%p 438=%p} target_d8_fields{%p,%p,%p} "
        "split_owner_slots{d8=%p e0=%p 1a0=%p 1c8=%p 228=%p 438=%p} "
        "split_owner_d8_fields{%p,%p,%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(callback),
        reinterpret_cast<void*>(callback_arg),
        reinterpret_cast<void*>(local_target),
        reinterpret_cast<void*>(local_ref),
        reinterpret_cast<void*>(split_context),
        reinterpret_cast<void*>(split_owner),
        reinterpret_cast<void*>(split_control),
        reinterpret_cast<void*>(target_d8),
        reinterpret_cast<void*>(ReadPointerIfReadable(local_target + 0xe0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(local_target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(local_target + 0x1c8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(local_target + 0x228)),
        reinterpret_cast<void*>(ReadPointerIfReadable(local_target + 0x438)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target_d8 + 0x10)),
        reinterpret_cast<void*>(split_owner_d8),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner + 0xe0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner + 0x1c8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner + 0x228)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner + 0x438)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner_d8 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner_d8 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(split_owner_d8 + 0x10)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(local_ref);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base +
        kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset + 7);
    return true;
  }

  if (libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkFastNilOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkFastNilOffset + 1) {
    const uintptr_t context =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
    const uintptr_t argument =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk fast nil "
        "off=0x%lx context=%p argument=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(context), reinterpret_cast<void*>(argument));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RBX] = 0;
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyTaskThunkFastNilOffset +
        2);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaTargetPostApplyTaskThunkReturnOffset ||
      libroblox_offset ==
          kStage6StartLuaTargetPostApplyTaskThunkReturnOffset + 1) {
    const uintptr_t result =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    char msg[700];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua post-apply task thunk return off=0x%lx "
        "result=%p result_fields{0=%p 8=%p 10=%p 18=%p 20=%p}\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(result),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x20)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(result);
    ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
        libroblox_base + kStage6StartLuaTargetPostApplyTaskThunkReturnOffset +
        3);
    return true;
  }

  if (libroblox_offset == kStage6StartLuaGateHelperOffset ||
      libroblox_offset == kStage6StartLuaGateHelperOffset + 1 ||
      libroblox_offset == kStage6StartLuaLoggedInHelperOffset ||
      libroblox_offset == kStage6StartLuaLoggedInHelperOffset + 1 ||
      libroblox_offset == kStage6StartLuaDeepStartOffset ||
      libroblox_offset == kStage6StartLuaDeepStartOffset + 1) {
    const bool is_deep = libroblox_offset == kStage6StartLuaDeepStartOffset ||
                         libroblox_offset == kStage6StartLuaDeepStartOffset + 1;
    const bool is_logged_in_helper =
        libroblox_offset == kStage6StartLuaLoggedInHelperOffset ||
        libroblox_offset == kStage6StartLuaLoggedInHelperOffset + 1;
    const uintptr_t function_offset =
        is_deep ? kStage6StartLuaDeepStartOffset
                : (is_logged_in_helper ? kStage6StartLuaLoggedInHelperOffset
                                       : kStage6StartLuaGateHelperOffset);
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
    if (is_logged_in_helper &&
        IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER") &&
        g_stage6_start_lua_owner_slot_028 != 0 &&
        g_stage6_start_lua_owner_slot_030 != 0) {
      *reinterpret_cast<uintptr_t*>(state + 0x08) =
          g_stage6_start_lua_owner_slot_028;
      *reinterpret_cast<uintptr_t*>(state + 0x10) =
          g_stage6_start_lua_owner_slot_030;
      *reinterpret_cast<uintptr_t*>(state + 0x18) =
          g_stage6_start_lua_owner_slot_038;
      char seed_msg[520];
      int seed_len =
          snprintf(seed_msg, sizeof(seed_msg),
                   "  [patch] Stage6 StartLua logged-in helper state seeded "
                   "object=%p fields{8=%p 10=%p 18=%p}\n",
                   reinterpret_cast<void*>(state),
                   reinterpret_cast<void*>(g_stage6_start_lua_owner_slot_028),
                   reinterpret_cast<void*>(g_stage6_start_lua_owner_slot_030),
                   reinterpret_cast<void*>(g_stage6_start_lua_owner_slot_038));
      if (seed_len > 0) {
        write(2, seed_msg, static_cast<size_t>(seed_len));
      }
    }

    char msg[900];
    int len = 0;
    if (is_logged_in_helper) {
      len = snprintf(
          msg, sizeof(msg),
          "  [trace] entered Stage6 logged-in StartLua helper off=0x%lx "
          "object=%p fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p} "
          "payload=%p payload0=0x%llx\n",
          static_cast<unsigned long>(libroblox_offset),
          reinterpret_cast<void*>(state),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(state + 0x30)),
          reinterpret_cast<void*>(payload),
          static_cast<unsigned long long>(payload_first));
    } else {
      len = snprintf(msg, sizeof(msg),
                     "  [trace] entered Stage6 %s StartLua off=0x%lx "
                     "state=%p phase=0x%x payload=%p payload0=0x%llx\n",
                     is_deep ? "deep" : "gate helper",
                     static_cast<unsigned long>(libroblox_offset),
                     reinterpret_cast<void*>(state), phase,
                     reinterpret_cast<void*>(payload),
                     static_cast<unsigned long long>(payload_first));
    }
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
      ucontext->uc_mcontext.gregs[REG_RIP] =
          static_cast<greg_t>(libroblox_base + function_offset + 1);
      return true;
    }
  }

  return false;
}

}  // namespace mocktail::legacy::internal
