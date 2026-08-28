#include "legacy/stage6_start_lua_fallbacks.h"

#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/runtime_environment.h"
#include "legacy/stage6_offsets.h"
#include "legacy/stage6_runtime.h"

namespace mocktail::legacy::internal {

extern "C" void mocktail_stage6_start_lua_copy_fake_event_base(void* out,
                                                               void* self) {
  auto* output = static_cast<uintptr_t*>(out);
  auto* event = static_cast<uintptr_t*>(self);
  if (output == nullptr || event == nullptr) {
    return;
  }

  const uintptr_t base = event[1];
  const uintptr_t refcount = event[2];
  output[0] = base;
  output[1] = refcount;

  static volatile sig_atomic_t copy_logs = 0;
  if (copy_logs < 8) {
    char msg[620];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartLua fake callback event copied base "
                 "event=%p out=%p base=%p ref=%p slots{428=%p 430=%p 438=%p}\n",
                 self, out, reinterpret_cast<void*>(base),
                 reinterpret_cast<void*>(refcount),
                 reinterpret_cast<void*>(ReadPointerIfReadable(base + 0x428)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(base + 0x430)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(base + 0x438)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++copy_logs;
  }
}

extern "C" void mocktail_stage6_start_lua_register_callback(void* self,
                                                            void* arg1,
                                                            void* arg2) {
  static volatile sig_atomic_t callback_logs = 0;
  static thread_local bool callback_continuation_in_progress = false;
  if (callback_logs >= 16) {
    return;
  }
  ++callback_logs;

  const uintptr_t callback_object = reinterpret_cast<uintptr_t>(arg2);
  const uintptr_t callback_vtable = ReadPointerIfReadable(callback_object);
  const uintptr_t callback_owner =
      ReadPointerIfReadable(callback_object + 0x08);
  const uintptr_t callback_next = ReadPointerIfReadable(callback_object + 0x20);
  const uintptr_t callback_vtable_continuation =
      ReadPointerIfReadable(callback_vtable + 0x30);
  const uintptr_t self_owner =
      ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08);
  const bool callback_owner_matches_installed_owner =
      callback_owner >= kStage5LowAddressThreshold &&
      callback_owner == self_owner;
  const uintptr_t effective_owner =
      callback_owner_matches_installed_owner ? callback_owner : self_owner;
  const uintptr_t owner_callback_target =
      ReadPointerIfReadable(effective_owner + 0x3f8);
  const uintptr_t owner_state = ReadPointerIfReadable(effective_owner + 0x418);
  const uintptr_t owner_table0 = ReadPointerIfReadable(effective_owner + 0x850);
  const uintptr_t owner_table0_ref =
      ReadPointerIfReadable(effective_owner + 0x858);
  const uintptr_t owner_table1 = ReadPointerIfReadable(effective_owner + 0x860);
  const uintptr_t owner_table1_ref =
      ReadPointerIfReadable(effective_owner + 0x868);

  char msg[1200];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartLua fallback callback target invoked "
      "self=%p arg1=%p arg2=%p cb{vtable=%p vtable30=%p owner=%p next=%p} "
      "effective_owner=%p owner{3f8=%p 418=%p t0=%p/%p t1=%p/%p} "
      "hint=mock lifecycle callback registration target\n",
      self, arg1, arg2, reinterpret_cast<void*>(callback_vtable),
      reinterpret_cast<void*>(callback_vtable_continuation),
      reinterpret_cast<void*>(callback_owner),
      reinterpret_cast<void*>(callback_next),
      reinterpret_cast<void*>(effective_owner),
      reinterpret_cast<void*>(owner_callback_target),
      reinterpret_cast<void*>(owner_state),
      reinterpret_cast<void*>(owner_table0),
      reinterpret_cast<void*>(owner_table0_ref),
      reinterpret_cast<void*>(owner_table1),
      reinterpret_cast<void*>(owner_table1_ref));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }

  if (!callback_continuation_in_progress &&
      IsEnabled("MOCKTAIL_CALL_STAGE6_START_LUA_CALLBACK_FAKE_EVENT") &&
      effective_owner >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(callback_vtable + 0x30, sizeof(uintptr_t))) {
    using Stage6StartLuaCallbackContinuationFn = void (*)(void*, void*);
    auto* continuation = reinterpret_cast<Stage6StartLuaCallbackContinuationFn>(
        callback_vtable_continuation);
    uintptr_t event_base =
        ReadPointerIfReadable(reinterpret_cast<uintptr_t>(arg1));
    if (event_base < kStage5LowAddressThreshold) {
      event_base = ReadPointerIfReadable(effective_owner + 0x38);
    }

    if (continuation != nullptr && event_base >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(event_base + 0x438, sizeof(uintptr_t))) {
      std::memset(g_stage6_start_lua_fake_event_vtable, 0,
                  sizeof(g_stage6_start_lua_fake_event_vtable));
      std::memset(g_stage6_start_lua_fake_event_object, 0,
                  sizeof(g_stage6_start_lua_fake_event_object));
      for (uintptr_t& slot : g_stage6_start_lua_fake_event_vtable) {
        slot = reinterpret_cast<uintptr_t>(
            &mocktail_stage6_start_lua_copy_fake_event_base);
      }
      g_stage6_start_lua_fake_event_object[0] =
          reinterpret_cast<uintptr_t>(g_stage6_start_lua_fake_event_vtable);
      g_stage6_start_lua_fake_event_object[1] = event_base;
      g_stage6_start_lua_fake_event_object[2] = 0;
      g_stage6_start_lua_fake_event_object[3] = effective_owner;

      char before_msg[760];
      int before_len = snprintf(
          before_msg, sizeof(before_msg),
          "  [patch] invoking Stage6 StartLua callback continuation with "
          "fake event callback=%p event=%p fn=%p owner=%p base=%p "
          "base_slots{428=%p 430=%p 438=%p}\n",
          arg2, static_cast<void*>(g_stage6_start_lua_fake_event_object),
          reinterpret_cast<void*>(continuation),
          reinterpret_cast<void*>(effective_owner),
          reinterpret_cast<void*>(event_base),
          reinterpret_cast<void*>(ReadPointerIfReadable(event_base + 0x428)),
          reinterpret_cast<void*>(ReadPointerIfReadable(event_base + 0x430)),
          reinterpret_cast<void*>(ReadPointerIfReadable(event_base + 0x438)));
      if (before_len > 0) {
        write(2, before_msg, static_cast<size_t>(before_len));
      }

      callback_continuation_in_progress = true;
      continuation(arg2, g_stage6_start_lua_fake_event_object);
      callback_continuation_in_progress = false;

      char after_msg[1280];
      const uintptr_t slot_428 = ReadPointerIfReadable(event_base + 0x428);
      const uintptr_t slot_430 = ReadPointerIfReadable(event_base + 0x430);
      const uintptr_t slot_438 = ReadPointerIfReadable(event_base + 0x438);
      int after_len = snprintf(
          after_msg, sizeof(after_msg),
          "  [patch] Stage6 StartLua fake-event continuation returned "
          "owner=%p base=%p base_slots{428=%p 430=%p 438=%p} "
          "slot428_fields{%p,%p,%p,%p} "
          "slot430_fields{%p,%p,%p,%p} "
          "slot438_fields{%p,%p,%p,%p}\n",
          reinterpret_cast<void*>(effective_owner),
          reinterpret_cast<void*>(event_base),
          reinterpret_cast<void*>(slot_428), reinterpret_cast<void*>(slot_430),
          reinterpret_cast<void*>(slot_438),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_428 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_428 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_428 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_428 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_430 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_430 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_430 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_430 + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_438 + 0x00)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_438 + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_438 + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot_438 + 0x18)));
      if (after_len > 0) {
        write(2, after_msg, static_cast<size_t>(after_len));
      }
    } else {
      char skip_msg[560];
      int skip_len = snprintf(
          skip_msg, sizeof(skip_msg),
          "  [patch] skipped Stage6 StartLua fake-event continuation "
          "callback=%p fn=%p owner=%p base=%p readable=%d\n",
          arg2, reinterpret_cast<void*>(continuation),
          reinterpret_cast<void*>(effective_owner),
          reinterpret_cast<void*>(event_base),
          event_base >= kStage5LowAddressThreshold &&
                  IsReadableMemoryRange(event_base + 0x438, sizeof(uintptr_t))
              ? 1
              : 0);
      if (skip_len > 0) {
        write(2, skip_msg, static_cast<size_t>(skip_len));
      }
    }
  }

  if (!callback_continuation_in_progress &&
      IsEnabled("MOCKTAIL_CALL_STAGE6_START_LUA_CALLBACK_CONTINUATION") &&
      effective_owner >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(callback_vtable + 0x30, sizeof(uintptr_t))) {
    using Stage6StartLuaCallbackContinuationFn = void (*)(void*, void*);
    auto* continuation = reinterpret_cast<Stage6StartLuaCallbackContinuationFn>(
        callback_vtable_continuation);
    if (continuation != nullptr) {
      char before_msg[520];
      int before_len =
          snprintf(before_msg, sizeof(before_msg),
                   "  [patch] invoking Stage6 StartLua callback continuation "
                   "callback=%p event=%p fn=%p owner=%p\n",
                   arg2, arg1, reinterpret_cast<void*>(continuation),
                   reinterpret_cast<void*>(effective_owner));
      if (before_len > 0) {
        write(2, before_msg, static_cast<size_t>(before_len));
      }
      callback_continuation_in_progress = true;
      continuation(arg2, arg1);
      callback_continuation_in_progress = false;

      const uintptr_t after_table0 =
          ReadPointerIfReadable(effective_owner + 0x850);
      const uintptr_t after_table0_ref =
          ReadPointerIfReadable(effective_owner + 0x858);
      const uintptr_t after_table1 =
          ReadPointerIfReadable(effective_owner + 0x860);
      const uintptr_t after_table1_ref =
          ReadPointerIfReadable(effective_owner + 0x868);
      char after_msg[520];
      int after_len =
          snprintf(after_msg, sizeof(after_msg),
                   "  [patch] Stage6 StartLua callback continuation returned "
                   "owner=%p tables{%p/%p %p/%p}\n",
                   reinterpret_cast<void*>(effective_owner),
                   reinterpret_cast<void*>(after_table0),
                   reinterpret_cast<void*>(after_table0_ref),
                   reinterpret_cast<void*>(after_table1),
                   reinterpret_cast<void*>(after_table1_ref));
      if (after_len > 0) {
        write(2, after_msg, static_cast<size_t>(after_len));
      }
    }
  }
}

extern "C" void mocktail_stage6_start_lua_noop_continuation(void* self,
                                                            void* arg1,
                                                            void* arg2) {
  bool copied_arg1_to_arg2 = false;
  const uintptr_t arg1_raw = reinterpret_cast<uintptr_t>(arg1);
  const uintptr_t arg2_raw = reinterpret_cast<uintptr_t>(arg2);
  if (IsEnabled("MOCKTAIL_STAGE6_START_LUA_CONTINUATION_COPY_ARG1_TO_ARG2") &&
      arg1_raw >= kStage5LowAddressThreshold &&
      arg2_raw >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(arg1_raw - 0x08, 0x30) &&
      IsReadableMemoryRange(arg2_raw - 0x08, 0x30) &&
      EnsureWritablePage(reinterpret_cast<void*>(arg2_raw - 0x08))) {
    std::memcpy(reinterpret_cast<void*>(arg2_raw - 0x08),
                reinterpret_cast<const void*>(arg1_raw - 0x08), 0x30);
    copied_arg1_to_arg2 = true;
  }

  static volatile sig_atomic_t noop_logs = 0;
  if (noop_logs < 8) {
    const uintptr_t self_raw = reinterpret_cast<uintptr_t>(self);
    const uintptr_t return_address =
        reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
    const uintptr_t return_offset =
        libroblox_base != 0 && return_address >= libroblox_base &&
                return_address <
                    libroblox_base + kLibrobloxExecutableSegmentEndOffset
            ? return_address - libroblox_base
            : 0;

    char msg[1320];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua noop continuation invoked "
        "self=%p arg1=%p arg2=%p copied_arg1_to_arg2=%d "
        "return=%p return_off=0x%lx "
        "self_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p 38=%p}\n",
        self, arg1, arg2, copied_arg1_to_arg2 ? 1 : 0,
        reinterpret_cast<void*>(return_address),
        static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw + 0x38)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua noop arg1 wide "
        "base=%p fields{m10=%p m8=%p 0=%p 8=%p 10=%p 18=%p "
        "20=%p 28=%p 30=%p 38=%p 40=%p 48=%p 50=%p 58=%p 60=%p}\n",
        arg1,
        reinterpret_cast<void*>(
            ReadPointerIfReadable(arg1_raw >= 0x10 ? arg1_raw - 0x10 : 0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw - 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x38)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x40)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x48)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x50)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x58)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x60)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua noop arg2 wide "
        "base=%p fields{m10=%p m8=%p 0=%p 8=%p 10=%p 18=%p "
        "20=%p 28=%p 30=%p 38=%p 40=%p 48=%p 50=%p 58=%p 60=%p}\n",
        arg2,
        reinterpret_cast<void*>(
            ReadPointerIfReadable(arg2_raw >= 0x10 ? arg2_raw - 0x10 : 0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw - 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x38)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x40)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x48)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x50)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x58)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x60)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }

    const uintptr_t arg1_p0 = ReadPointerIfReadable(arg1_raw + 0x00);
    const uintptr_t arg1_p8 = ReadPointerIfReadable(arg1_raw + 0x08);
    const uintptr_t arg1_p10 = ReadPointerIfReadable(arg1_raw + 0x10);
    const uintptr_t arg1_p18 = ReadPointerIfReadable(arg1_raw + 0x18);
    const uintptr_t arg2_p0 = ReadPointerIfReadable(arg2_raw + 0x00);
    const uintptr_t arg2_p8 = ReadPointerIfReadable(arg2_raw + 0x08);
    const uintptr_t arg2_p10 = ReadPointerIfReadable(arg2_raw + 0x10);
    const uintptr_t arg2_p18 = ReadPointerIfReadable(arg2_raw + 0x18);
    len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua noop nested "
        "arg1{0=%p:%p/%p/%p/%p 8=%p:%p/%p/%p/%p "
        "10=%p:%p/%p/%p/%p 18=%p:%p/%p/%p/%p} "
        "arg2{0=%p:%p/%p/%p/%p 8=%p:%p/%p/%p/%p "
        "10=%p:%p/%p/%p/%p 18=%p:%p/%p/%p/%p}\n",
        reinterpret_cast<void*>(arg1_p0),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p0 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p0 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p0 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p0 + 0x18)),
        reinterpret_cast<void*>(arg1_p8),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p8 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p8 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p8 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p8 + 0x18)),
        reinterpret_cast<void*>(arg1_p10),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p10 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p10 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p10 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p10 + 0x18)),
        reinterpret_cast<void*>(arg1_p18),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p18 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p18 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p18 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_p18 + 0x18)),
        reinterpret_cast<void*>(arg2_p0),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p0 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p0 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p0 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p0 + 0x18)),
        reinterpret_cast<void*>(arg2_p8),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p8 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p8 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p8 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p8 + 0x18)),
        reinterpret_cast<void*>(arg2_p10),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p10 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p10 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p10 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p10 + 0x18)),
        reinterpret_cast<void*>(arg2_p18),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p18 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p18 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p18 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p18 + 0x18)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++noop_logs;
  }
}

extern "C" void* mocktail_stage6_start_lua_copy_empty_callback_table(
    void* out, void* self) {
  if (out != nullptr) {
    std::memset(out, 0, 0x30);
    std::memset(g_stage6_start_lua_callback_bucket_scratch, 0,
                sizeof(g_stage6_start_lua_callback_bucket_scratch));
    auto* raw = static_cast<unsigned char*>(out);
    *reinterpret_cast<uintptr_t*>(raw + 0x00) =
        reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_bucket_scratch);
    *reinterpret_cast<uintptr_t*>(raw + 0x08) =
        sizeof(g_stage6_start_lua_callback_bucket_scratch) / sizeof(uintptr_t);
    *reinterpret_cast<uintptr_t*>(raw + 0x10) = 0;
    *reinterpret_cast<uintptr_t*>(raw + 0x18) = 0;
    *reinterpret_cast<float*>(raw + 0x20) = 1.0f;
  }

  static volatile sig_atomic_t copy_logs = 0;
  if (copy_logs < 8) {
    char msg[420];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua fallback callback empty table copied "
        "out=%p self=%p owner=%p buckets=%p count=%zu\n",
        out, self,
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08)),
        static_cast<void*>(g_stage6_start_lua_callback_bucket_scratch),
        sizeof(g_stage6_start_lua_callback_bucket_scratch) / sizeof(uintptr_t));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++copy_logs;
  }
  return out;
}

uintptr_t LogStage6StartLuaFallbackCallbackMethod(
    const char* slot_name, void* self, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t return_address,
    uintptr_t frame) {
  static volatile sig_atomic_t noop_logs = 0;
  if (noop_logs < 32) {
    const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
    const uintptr_t return_offset =
        libroblox_base != 0 && return_address >= libroblox_base &&
                return_address <
                    libroblox_base + kLibrobloxExecutableSegmentEndOffset
            ? return_address - libroblox_base
            : 0;
    uintptr_t parent_return_address = 0;
    uintptr_t parent_return_offset = 0;
    const uintptr_t parent_frame = ReadPointerIfReadable(frame);
    if (IsReadableMemoryRange(parent_frame + sizeof(uintptr_t),
                              sizeof(uintptr_t))) {
      parent_return_address =
          *reinterpret_cast<const uintptr_t*>(parent_frame + sizeof(uintptr_t));
      if (libroblox_base != 0 && parent_return_address >= libroblox_base &&
          parent_return_address <
              libroblox_base + kLibrobloxExecutableSegmentEndOffset) {
        parent_return_offset = parent_return_address - libroblox_base;
      }
    }
    const uintptr_t self_raw = reinterpret_cast<uintptr_t>(self);
    const uintptr_t arg1_raw = arg1;
    const uintptr_t arg2_raw = arg2;
    const uintptr_t arg4_raw = arg4;
    const uintptr_t arg5_raw = arg5;
    char msg[1560];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua fallback callback noop method %s "
        "self=%p vtable=%p return=%p return_off=0x%lx "
        "parent_return=%p parent_return_off=0x%lx "
        "args{%p,%p,%p,%p,%p} owner=%p "
        "arg1_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p} "
        "arg2_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p}\n",
        slot_name, self,
        reinterpret_cast<void*>(ReadPointerIfReadable(self_raw)),
        reinterpret_cast<void*>(return_address),
        static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(parent_return_address),
        static_cast<unsigned long>(parent_return_offset),
        reinterpret_cast<void*>(arg1), reinterpret_cast<void*>(arg2),
        reinterpret_cast<void*>(arg3), reinterpret_cast<void*>(arg4),
        reinterpret_cast<void*>(arg5),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg1_raw + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x28)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    const uintptr_t arg2_p20 = ReadPointerIfReadable(arg2_raw + 0x20);
    const uintptr_t arg2_p20_vtable = ReadPointerIfReadable(arg2_p20 + 0x00);
    auto libroblox_offset = [libroblox_base](uintptr_t value) -> uintptr_t {
      return libroblox_base != 0 && value >= libroblox_base &&
                     value <
                         libroblox_base + kLibrobloxExecutableSegmentEndOffset
                 ? value - libroblox_base
                 : 0;
    };
    char detail_msg[1900];
    int detail_len = snprintf(
        detail_msg, sizeof(detail_msg),
        "  [patch] Stage6 StartLua fallback callback detail %s "
        "arg2_p20=%p task_vtable=%p task_vtable_off=0x%lx "
        "task_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p 38=%p} "
        "task_vslots{0=%p/off=0x%lx 8=%p/off=0x%lx 10=%p/off=0x%lx "
        "18=%p/off=0x%lx 20=%p/off=0x%lx 28=%p/off=0x%lx} "
        "arg4_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p} "
        "arg5_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p}\n",
        slot_name, reinterpret_cast<void*>(arg2_p20),
        reinterpret_cast<void*>(arg2_p20_vtable),
        static_cast<unsigned long>(libroblox_offset(arg2_p20_vtable)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x38)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x00)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x00))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x08)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x08))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x10)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x10))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x18)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x18))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x20)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x20))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20_vtable + 0x28)),
        static_cast<unsigned long>(
            libroblox_offset(ReadPointerIfReadable(arg2_p20_vtable + 0x28))),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg4_raw + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg5_raw + 0x28)));
    if (detail_len > 0) {
      write(2, detail_msg, static_cast<size_t>(detail_len));
    }
    char wide_msg[2800];
    int wide_len = snprintf(
        wide_msg, sizeof(wide_msg),
        "  [patch] Stage6 StartLua fallback callback wide %s "
        "arg2_wide{30=%p 38=%p 40=%p 48=%p 50=%p 58=%p} "
        "task_wide{40=%p 48=%p 50=%p 58=%p 60=%p 68=%p 70=%p 78=%p "
        "80=%p 88=%p 90=%p 98=%p a0=%p b0=%p c0=%p d0=%p e0=%p "
        "f0=%p 100=%p 110=%p 120=%p 130=%p 140=%p 150=%p 158=%p "
        "168=%p 170=%p 180=%p 188=%p 198=%p 1a0=%p 1b0=%p 1b8=%p "
        "1c8=%p 1d0=%p 1e0=%p}\n",
        slot_name,
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x30)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x38)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x40)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x48)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x50)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_raw + 0x58)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x40)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x48)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x50)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x58)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x60)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x68)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x70)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x78)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x80)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x88)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x90)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x98)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xa0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xb0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xc0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xd0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xe0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0xf0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x100)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x110)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x120)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x130)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x140)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x150)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x168)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x170)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x180)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x188)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x198)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1b0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1b8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1c8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1d0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(arg2_p20 + 0x1e0)));
    if (wide_len > 0) {
      write(2, wide_msg, static_cast<size_t>(wide_len));
    }
    ++noop_logs;
  }
  return 0;
}

uintptr_t MaybeInvokeStage6StartLuaSlot8Task(void* self, uintptr_t arg1,
                                             uintptr_t arg2, uintptr_t arg3,
                                             uintptr_t arg4, uintptr_t arg5) {
  if (!IsEnabled("MOCKTAIL_STAGE6_START_LUA_SLOT8_INLINE_TASK")) {
    return 0;
  }

  const uintptr_t task = ReadPointerIfReadable(arg2 + 0x20);
  const uintptr_t task_vtable = ReadPointerIfReadable(task);
  const int method_offset =
      GetEnvInt("MOCKTAIL_STAGE6_START_LUA_SLOT8_TASK_METHOD_OFFSET", 0x18);
  if (task < kStage5LowAddressThreshold ||
      task_vtable < kStage5LowAddressThreshold || method_offset < 0 ||
      !IsReadableMemoryRange(
          task_vtable + static_cast<uintptr_t>(method_offset),
          sizeof(uintptr_t))) {
    std::cerr << "  [patch] Stage6 StartLua slot8 inline task skipped"
              << " self=" << self << " arg1=" << reinterpret_cast<void*>(arg1)
              << " arg2=" << reinterpret_cast<void*>(arg2)
              << " task=" << reinterpret_cast<void*>(task)
              << " vtable=" << reinterpret_cast<void*>(task_vtable)
              << " method_offset=0x" << std::hex << method_offset << std::dec
              << '\n'
              << std::flush;
    return 0;
  }

  const uintptr_t method = ReadPointerIfReadable(
      task_vtable + static_cast<uintptr_t>(method_offset));
  const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
  const uintptr_t method_offset_in_lib =
      libroblox_base != 0 && method >= libroblox_base &&
              method < libroblox_base + kLibrobloxExecutableSegmentEndOffset
          ? method - libroblox_base
          : 0;
  std::cerr << "  [patch] Stage6 StartLua slot8 inline task invoke"
            << " self=" << self << " args{" << reinterpret_cast<void*>(arg1)
            << ',' << reinterpret_cast<void*>(arg2) << ','
            << reinterpret_cast<void*>(arg3) << ','
            << reinterpret_cast<void*>(arg4) << ','
            << reinterpret_cast<void*>(arg5) << "}"
            << " task=" << reinterpret_cast<void*>(task)
            << " vtable=" << reinterpret_cast<void*>(task_vtable)
            << " method=" << reinterpret_cast<void*>(method) << "/off=0x"
            << std::hex << method_offset_in_lib << " method_offset=0x"
            << method_offset << std::dec << '\n'
            << std::flush;

  using TaskMethod = uintptr_t (*)(void*);
  auto* fn = reinterpret_cast<TaskMethod>(method);
  return fn(reinterpret_cast<void*>(task));
}

extern "C" uintptr_t mocktail_stage6_start_lua_noop_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  return LogStage6StartLuaFallbackCallbackMethod(
      "slot=generic-noop", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
}

extern "C" uintptr_t mocktail_stage6_start_lua_slot8_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  LogStage6StartLuaFallbackCallbackMethod(
      "slot=8", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
  return MaybeInvokeStage6StartLuaSlot8Task(self, arg1, arg2, arg3, arg4, arg5);
}

extern "C" uintptr_t mocktail_stage6_start_lua_slot12_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  return LogStage6StartLuaFallbackCallbackMethod(
      "slot=12", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
}

extern "C" uintptr_t mocktail_stage6_start_lua_slot13_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  return LogStage6StartLuaFallbackCallbackMethod(
      "slot=13", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
}

extern "C" uintptr_t mocktail_stage6_start_lua_slot14_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  return LogStage6StartLuaFallbackCallbackMethod(
      "slot=14", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
}

extern "C" uintptr_t mocktail_stage6_start_lua_slot15_callback_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  return LogStage6StartLuaFallbackCallbackMethod(
      "slot=15", self, arg1, arg2, arg3, arg4, arg5,
      reinterpret_cast<uintptr_t>(__builtin_return_address(0)),
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0)));
}

extern "C" uintptr_t mocktail_stage6_start_lua_target_callback_pair_method(
    void* self, uintptr_t pair, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  const uintptr_t owner =
      ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08);
  uintptr_t owner_ref = ReadPointerIfReadable(owner + 0x10);
  if (owner_ref < kStage5LowAddressThreshold) {
    owner_ref = ReadPointerIfReadable(owner + 0x858);
  }
  bool wrote_pair = false;
  if (!IsDisabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_PAIR_OWNER") &&
      pair >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(pair, 2 * sizeof(uintptr_t)) &&
      owner >= kStage5LowAddressThreshold &&
      EnsureWritablePage(reinterpret_cast<void*>(pair))) {
    *reinterpret_cast<uintptr_t*>(pair + 0x00) = owner;
    *reinterpret_cast<uintptr_t*>(pair + 0x08) = owner_ref;
    wrote_pair = true;
  }

  static volatile sig_atomic_t pair_logs = 0;
  if (pair_logs < 16) {
    char msg[900];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartLua target callback pair method "
                 "self=%p pair=%p pair_fields{%p,%p} args{%p,%p,%p,%p} "
                 "owner=%p owner_ref=%p wrote_pair=%d\n",
                 self, reinterpret_cast<void*>(pair),
                 reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x00)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(pair + 0x08)),
                 reinterpret_cast<void*>(arg2), reinterpret_cast<void*>(arg3),
                 reinterpret_cast<void*>(arg4), reinterpret_cast<void*>(arg5),
                 reinterpret_cast<void*>(owner),
                 reinterpret_cast<void*>(owner_ref), wrote_pair ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++pair_logs;
  }
  return 0;
}

extern "C" uintptr_t mocktail_stage6_start_lua_target_callback_platform_method(
    void* self, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
    uintptr_t arg5) {
  static volatile sig_atomic_t platform_logs = 0;
  if (platform_logs < 16) {
    char msg[860];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua target callback platform method "
        "self=%p args{%p,%p,%p,%p,%p} owner=%p\n",
        self, reinterpret_cast<void*>(arg1), reinterpret_cast<void*>(arg2),
        reinterpret_cast<void*>(arg3), reinterpret_cast<void*>(arg4),
        reinterpret_cast<void*>(arg5),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++platform_logs;
  }
  return 0;
}

void SyncStage6StartLuaTargetCallbackSurfaceFields(uintptr_t callback) {
  if (IsDisabled(
          "MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_SURFACE_SYNC")) {
    return;
  }
  if (callback < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(callback + 0x478, sizeof(uintptr_t))) {
    return;
  }

  const uintptr_t owner = ReadPointerIfReadable(callback + 0x08);
  if (owner < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(owner + 0x478, sizeof(uintptr_t)) ||
      !EnsureWritablePage(reinterpret_cast<void*>(callback + 0x458))) {
    return;
  }

  *reinterpret_cast<uintptr_t*>(callback + 0x458) =
      ReadPointerIfReadable(owner + 0x458);
  *reinterpret_cast<uintptr_t*>(callback + 0x460) =
      ReadPointerIfReadable(owner + 0x460);
  *reinterpret_cast<uintptr_t*>(callback + 0x468) =
      ReadPointerIfReadable(owner + 0x468);
  *reinterpret_cast<uintptr_t*>(callback + 0x470) =
      ReadPointerIfReadable(owner + 0x470);
  *reinterpret_cast<uintptr_t*>(callback + 0x478) =
      ReadPointerIfReadable(owner + 0x478);

  *reinterpret_cast<uintptr_t*>(callback + 0x158) =
      ReadPointerIfReadable(owner + 0x158);
  *reinterpret_cast<uintptr_t*>(callback + 0x1a0) =
      ReadPointerIfReadable(owner + 0x1a0);
  *reinterpret_cast<uintptr_t*>(callback + 0x1b8) =
      ReadPointerIfReadable(owner + 0x1b8);
}

extern "C" uintptr_t mocktail_stage6_start_lua_target_callback_resume_graphics(
    void* self, uintptr_t active) {
  SyncStage6StartLuaTargetCallbackSurfaceFields(
      reinterpret_cast<uintptr_t>(self));
  static volatile sig_atomic_t resume_logs = 0;
  if (resume_logs < 8) {
    const uintptr_t target = reinterpret_cast<uintptr_t>(self);
    char msg[760];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua target callback resume graphics "
        "self=%p active=%p fields{158=%p 1a0=%p 1b8=%p 458=%p 468=%p "
        "478=%p}\n",
        self, reinterpret_cast<void*>(active),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1b8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x458)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x468)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x478)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++resume_logs;
  }
  return 0;
}

extern "C" uintptr_t mocktail_stage6_start_lua_target_callback_surface_params(
    void* self, void* out) {
  const uintptr_t target = reinterpret_cast<uintptr_t>(self);
  SyncStage6StartLuaTargetCallbackSurfaceFields(target);
  const uintptr_t owner = ReadPointerIfReadable(target + 0x08);
  const uintptr_t out_raw = reinterpret_cast<uintptr_t>(out);
  const uintptr_t frame =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  const uintptr_t native_payload = frame >= 0x10 ? frame + 0x10 : 0;
  bool copied_payload = false;
  bool cleared_release_ref = false;
  if (out_raw >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(out_raw, 0x30) &&
      EnsureWritablePage(reinterpret_cast<void*>(out_raw))) {
    if (native_payload >= kStage5LowAddressThreshold &&
        IsReadableMemoryRange(native_payload, 0x28)) {
      std::memcpy(out, reinterpret_cast<const void*>(native_payload), 0x28);
      *reinterpret_cast<uintptr_t*>(out_raw + 0x28) = 0;
      copied_payload = true;

      uintptr_t release_ref = ReadPointerIfReadable(out_raw + 0x08);
      if (release_ref != 0 &&
          (release_ref < kStage5LowAddressThreshold ||
           !IsReadableMemoryRange(release_ref, sizeof(uintptr_t)))) {
        *reinterpret_cast<uintptr_t*>(out_raw + 0x08) = 0;
        cleared_release_ref = true;
      }
    } else {
      std::memset(out, 0, 0x30);
    }
  }

  static volatile sig_atomic_t surface_logs = 0;
  if (surface_logs < 8) {
    char msg[1040];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua target callback surface params "
        "self=%p out=%p owner=%p owner_fields{438=%p 448=%p 458=%p "
        "460=%p 468=%p 470=%p 478=%p} payload=%p copied=%d "
        "cleared_release_ref=%d payload_fields{0=%p 8=%p 10=%p 18=%p "
        "20=%p} out_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p}\n",
        self, out, reinterpret_cast<void*>(owner),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x438)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x448)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x458)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x460)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x468)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x470)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x478)),
        reinterpret_cast<void*>(native_payload), copied_payload ? 1 : 0,
        cleared_release_ref ? 1 : 0,
        reinterpret_cast<void*>(ReadPointerIfReadable(native_payload + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(native_payload + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(native_payload + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(native_payload + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(native_payload + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(out_raw + 0x28)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++surface_logs;
  }
  return 0;
}

extern "C" uintptr_t mocktail_stage6_start_lua_target_callback_resume_state(
    void* self) {
  static volatile sig_atomic_t state_logs = 0;
  if (state_logs < 8) {
    const uintptr_t target = reinterpret_cast<uintptr_t>(self);
    char msg[640];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua target callback resume state "
        "self=%p result=3 fields{158=%p 1a0=%p 1b8=%p}\n",
        self, reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1b8)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++state_logs;
  }
  return 3;
}

extern "C" void mocktail_stage6_start_lua_send_app_event_callback(void* self,
                                                                  void* out) {
  constexpr uintptr_t kSendAppEventGameLoadedReturnOffset = 0x2f50db7;
  constexpr uintptr_t kSendAppEventAppReadyReturnOffset = 0x2f50ed5;
  static volatile sig_atomic_t send_event_logs = 0;
  const uintptr_t out_raw = reinterpret_cast<uintptr_t>(out);
  char out_10_string[96];
  char out_18_string[96];
  char out_30_string[96];
  ReadLibcxxStringPreview(out_raw + 0x10, out_10_string, sizeof(out_10_string));
  ReadLibcxxStringPreview(out_raw + 0x18, out_18_string, sizeof(out_18_string));
  ReadLibcxxStringPreview(out_raw + 0x30, out_30_string, sizeof(out_30_string));
  const uintptr_t return_address =
      reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
  const uintptr_t return_offset =
      libroblox_base != 0 && return_address >= libroblox_base &&
              return_address <
                  libroblox_base + kLibrobloxExecutableSegmentEndOffset
          ? return_address - libroblox_base
          : 0;
  if (send_event_logs < 16) {
    const uintptr_t self_raw = reinterpret_cast<uintptr_t>(self);
    const uintptr_t owner =
        ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x08);
    const uintptr_t self_vtable = ReadPointerIfReadable(self_raw);
    const uintptr_t out_00 = ReadPointerIfReadable(out_raw + 0x00);
    const uintptr_t out_08 = ReadPointerIfReadable(out_raw + 0x08);
    const uintptr_t out_10 = ReadPointerIfReadable(out_raw + 0x10);
    const uintptr_t out_18 = ReadPointerIfReadable(out_raw + 0x18);
    const uintptr_t out_20 = ReadPointerIfReadable(out_raw + 0x20);
    const uintptr_t out_28 = ReadPointerIfReadable(out_raw + 0x28);
    const uintptr_t out_30 = ReadPointerIfReadable(out_raw + 0x30);
    const uintptr_t out_38 = ReadPointerIfReadable(out_raw + 0x38);
    char msg[1580];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua fallback SendAppEvent callback "
        "self=%p vtable=%p event=%p return=%p return_off=0x%lx "
        "owner=%p owner_slots{028=%p 030=%p 038=%p 3f8=%p 418=%p "
        "448=%p 850=%p/%p 860=%p/%p} "
        "event_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p 38=%p} "
        "strings{10=\"%s\" 18=\"%s\" 30=\"%s\"}\n",
        self, reinterpret_cast<void*>(self_vtable), out,
        reinterpret_cast<void*>(return_address),
        static_cast<unsigned long>(return_offset),
        reinterpret_cast<void*>(owner),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x028)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x030)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x038)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x3f8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x418)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x448)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x850)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x858)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x860)),
        reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x868)),
        reinterpret_cast<void*>(out_00), reinterpret_cast<void*>(out_08),
        reinterpret_cast<void*>(out_10), reinterpret_cast<void*>(out_18),
        reinterpret_cast<void*>(out_20), reinterpret_cast<void*>(out_28),
        reinterpret_cast<void*>(out_30), reinterpret_cast<void*>(out_38),
        out_10_string, out_18_string, out_30_string);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++send_event_logs;
  }

  const char* notification_type = "APP_READY";
  const char* dispatch_flag =
      "MOCKTAIL_STAGE6_SEND_APP_EVENT_DISPATCH_APP_READY";
  if (return_offset == kSendAppEventGameLoadedReturnOffset) {
    notification_type = "GAME_LOADED";
    dispatch_flag = "MOCKTAIL_STAGE6_SEND_APP_EVENT_DISPATCH_GAME_LOADED";
  } else if (return_offset == kSendAppEventAppReadyReturnOffset) {
    notification_type = "APP_READY";
    dispatch_flag = "MOCKTAIL_STAGE6_SEND_APP_EVENT_DISPATCH_APP_READY";
  }

  if (!IsDisabled(dispatch_flag) && g_vm_for_main_thread_pump != nullptr) {
    JNIEnv* env = g_vm_for_main_thread_pump->GetJNIEnv();
    g_vm_for_main_thread_pump->RestoreFunctions();
    if (env != nullptr) {
      jclass native_gl_java_class =
          env->FindClass("com/roblox/engine/jni/NativeGLJavaInterface");
      jmethodID notify = env->GetStaticMethodID(
          native_gl_java_class, "onDataModelNotificationCallback",
          "(Ljava/lang/String;Ljava/lang/String;)V");
      if (notify != nullptr) {
        jstring type = env->NewStringUTF(notification_type);
        jstring data = env->NewStringUTF("");
        env->CallStaticVoidMethod(native_gl_java_class, notify, type, data);
        char msg[120];
        int len =
            snprintf(msg, sizeof(msg),
                     "  [patch] Stage6 SendAppEvent dispatched %s to JNI\n",
                     notification_type);
        if (len > 0) {
          write(2, msg, static_cast<size_t>(len));
        }
      }
    }
  }
}

uintptr_t InstallStage6StartLuaTargetCallbackObject(uintptr_t target,
                                                    uintptr_t context,
                                                    const char* reason) {
  if (!IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_OBJECT") ||
      target < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(target + 0x438, sizeof(uintptr_t))) {
    return 0;
  }

  auto** slot = reinterpret_cast<void**>(target + 0x438);
  uintptr_t current = ReadPointerIfReadable(target + 0x438);
  if (current >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(current, sizeof(uintptr_t)) &&
      ReadPointerIfReadable(current) >= kStage5LowAddressThreshold) {
    return current;
  }

  std::memset(g_stage6_start_lua_target_callback_object_vtable, 0,
              sizeof(g_stage6_start_lua_target_callback_object_vtable));
  for (uintptr_t& entry : g_stage6_start_lua_target_callback_object_vtable) {
    entry = reinterpret_cast<uintptr_t>(&NullVtableStub);
  }
  g_stage6_start_lua_target_callback_object_vtable[3] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_target_callback_pair_method);
  g_stage6_start_lua_target_callback_object_vtable[4] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_target_callback_platform_method);
  g_stage6_start_lua_target_callback_object_vtable[5] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_target_callback_resume_graphics);
  g_stage6_start_lua_target_callback_object_vtable[6] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_target_callback_surface_params);
  g_stage6_start_lua_target_callback_object_vtable[17] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_target_callback_resume_state);

  const uintptr_t target_vtable_before = ReadPointerIfReadable(target);
  const uintptr_t target_vtable_slot6 =
      ReadPointerIfReadable(target_vtable_before + 0x30);
  bool seeded_target_vtable = false;
  if (target_vtable_before < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(target_vtable_before + 0x30, sizeof(uintptr_t)) ||
      target_vtable_slot6 < kStage5LowAddressThreshold) {
    auto** target_vtable_slot = reinterpret_cast<void**>(target);
    if (EnsureWritablePage(target_vtable_slot)) {
      *target_vtable_slot = g_stage6_start_lua_target_callback_object_vtable;
      seeded_target_vtable = true;
    } else {
      char fail_msg[480];
      int fail_len =
          snprintf(fail_msg, sizeof(fail_msg),
                   "  [patch] Stage6 StartLua target vtable mprotect failed "
                   "target=%p old_vtable=%p old_slot6=%p errno=%d\n",
                   reinterpret_cast<void*>(target),
                   reinterpret_cast<void*>(target_vtable_before),
                   reinterpret_cast<void*>(target_vtable_slot6), errno);
      if (fail_len > 0) {
        write(2, fail_msg, static_cast<size_t>(fail_len));
      }
    }
  }

  std::memset(g_stage6_start_lua_target_callback_object, 0,
              sizeof(g_stage6_start_lua_target_callback_object));
  SeedStage6FakeIntrusiveRefcount(
      reinterpret_cast<unsigned char*>(
          g_stage6_start_lua_target_callback_object),
      sizeof(g_stage6_start_lua_target_callback_object));
  g_stage6_start_lua_target_callback_object[0] = reinterpret_cast<uintptr_t>(
      g_stage6_start_lua_target_callback_object_vtable);
  g_stage6_start_lua_target_callback_object[1] = target;
  g_stage6_start_lua_target_callback_object[2] = context;
  SyncStage6StartLuaTargetCallbackSurfaceFields(
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_target_callback_object));

  if (!EnsureWritablePage(slot)) {
    char fail_msg[460];
    int fail_len = snprintf(
        fail_msg, sizeof(fail_msg),
        "  [patch] Stage6 StartLua target callback object mprotect failed "
        "target=%p slot=%p old=%p errno=%d\n",
        reinterpret_cast<void*>(target), static_cast<void*>(slot),
        reinterpret_cast<void*>(current), errno);
    if (fail_len > 0) {
      write(2, fail_msg, static_cast<size_t>(fail_len));
    }
    return 0;
  }

  *slot = g_stage6_start_lua_target_callback_object;
  char msg[1120];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] installed Stage6 StartLua target callback object "
      "target=%p context=%p slot=0x438 old=%p object=%p vtable=%p "
      "target_vtable_old=%p target_vtable_new=%p old_slot6=%p "
      "seeded_target_vtable=%d target_fields{458=%p 468=%p 478=%p}",
      reinterpret_cast<void*>(target), reinterpret_cast<void*>(context),
      reinterpret_cast<void*>(current),
      static_cast<void*>(g_stage6_start_lua_target_callback_object),
      static_cast<void*>(g_stage6_start_lua_target_callback_object_vtable),
      reinterpret_cast<void*>(target_vtable_before),
      reinterpret_cast<void*>(ReadPointerIfReadable(target)),
      reinterpret_cast<void*>(target_vtable_slot6),
      seeded_target_vtable ? 1 : 0,
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x458)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x468)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x478)));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return reinterpret_cast<uintptr_t>(g_stage6_start_lua_target_callback_object);
}

uintptr_t PrepareStage6StartLuaResult20SplitCallbackContext(
    uintptr_t callback, uintptr_t source_pair) {
  g_stage6_start_lua_result20_callback_split_callback = 0;
  g_stage6_start_lua_result20_callback_split_source_pair = 0;
  g_stage6_start_lua_result20_callback_split_context = 0;

  if (source_pair < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(source_pair, 2 * sizeof(uintptr_t))) {
    return 0;
  }

  const uintptr_t owner = ReadPointerIfReadable(source_pair);
  if (owner < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(owner, sizeof(uintptr_t))) {
    return 0;
  }
  bool backfilled_owner_ref = false;
  const uintptr_t source_ref = ReadPointerIfReadable(source_pair + 0x08);
  if (IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_BACKFILL_"
                "OWNER_REF") &&
      source_ref >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(owner + 0x10, sizeof(uintptr_t)) &&
      EnsureWritablePage(reinterpret_cast<void*>(owner + 0x10))) {
    if (ReadPointerIfReadable(owner + 0x08) == 0 &&
        IsReadableMemoryRange(owner + 0x08, sizeof(uintptr_t))) {
      *reinterpret_cast<uintptr_t*>(owner + 0x08) = owner;
    }
    if (ReadPointerIfReadable(owner + 0x10) == 0) {
      *reinterpret_cast<uintptr_t*>(owner + 0x10) = source_ref;
      backfilled_owner_ref = true;
    }
  }

  std::memset(g_stage6_start_lua_result20_callback_context_scratch, 0,
              sizeof(g_stage6_start_lua_result20_callback_context_scratch));
  std::memset(g_stage6_start_lua_result20_callback_control_block, 0,
              sizeof(g_stage6_start_lua_result20_callback_control_block));
  *reinterpret_cast<uintptr_t*>(
      g_stage6_start_lua_result20_callback_control_block) =
      reinterpret_cast<uintptr_t>(kFallbackVtable);
  *reinterpret_cast<uint64_t*>(
      g_stage6_start_lua_result20_callback_control_block + 0x08) = 0x100000;
  *reinterpret_cast<uint64_t*>(
      g_stage6_start_lua_result20_callback_control_block + 0x10) = 0x100000;
  g_stage6_start_lua_result20_callback_context_scratch[0] = owner;
  g_stage6_start_lua_result20_callback_context_scratch[1] =
      reinterpret_cast<uintptr_t>(
          g_stage6_start_lua_result20_callback_control_block);

  g_stage6_start_lua_result20_callback_split_callback = callback;
  g_stage6_start_lua_result20_callback_split_source_pair = source_pair;
  g_stage6_start_lua_result20_callback_split_context =
      reinterpret_cast<uintptr_t>(
          g_stage6_start_lua_result20_callback_context_scratch);
  char msg[780];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartLua resolver result20 split callback context "
      "callback=%p context=%p source_pair=%p owner=%p control=%p "
      "source_pair_fields{%p,%p} backfilled_owner_ref=%d\n",
      reinterpret_cast<void*>(callback),
      reinterpret_cast<void*>(
          g_stage6_start_lua_result20_callback_split_context),
      reinterpret_cast<void*>(source_pair), reinterpret_cast<void*>(owner),
      static_cast<void*>(g_stage6_start_lua_result20_callback_control_block),
      reinterpret_cast<void*>(ReadPointerIfReadable(source_pair + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(source_pair + 0x08)),
      backfilled_owner_ref ? 1 : 0);
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return g_stage6_start_lua_result20_callback_split_context;
}

extern "C" uintptr_t mocktail_stage6_start_lua_synthetic_instance_slot40(
    void* self) {
  static volatile sig_atomic_t slot40_logs = 0;
  if (slot40_logs < 8) {
    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua synthetic Instance slot40 "
        "self=%p fields{d8=%p e0=%p 1a0=%p 228=%p}\n",
        self,
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0xd8)),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0xe0)),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x1a0)),
        reinterpret_cast<void*>(
            ReadPointerIfReadable(reinterpret_cast<uintptr_t>(self) + 0x228)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++slot40_logs;
  }
  return 0;
}

extern "C" uintptr_t mocktail_stage6_start_lua_synthetic_instance_slot158(
    void* self, uintptr_t arg) {
  static volatile sig_atomic_t slot158_logs = 0;
  if (slot158_logs < 8) {
    char msg[420];
    int len = snprintf(msg, sizeof(msg),
                       "  [patch] Stage6 StartLua synthetic Instance slot158 "
                       "self=%p arg=%p\n",
                       self, reinterpret_cast<void*>(arg));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++slot158_logs;
  }
  return 0;
}

uintptr_t PrepareStage6StartLuaSyntheticInstanceSource(uintptr_t source_value,
                                                       const char* reason) {
  std::memset(g_stage6_start_lua_synthetic_instance_object, 0,
              sizeof(g_stage6_start_lua_synthetic_instance_object));
  std::memset(g_stage6_start_lua_synthetic_instance_vtable, 0,
              sizeof(g_stage6_start_lua_synthetic_instance_vtable));
  std::memset(g_stage6_start_lua_synthetic_instance_control_block, 0,
              sizeof(g_stage6_start_lua_synthetic_instance_control_block));
  std::memset(g_stage6_start_lua_synthetic_instance_name, 0,
              sizeof(g_stage6_start_lua_synthetic_instance_name));

  SeedStage6FakeIntrusiveRefcount(
      g_stage6_start_lua_synthetic_instance_object,
      sizeof(g_stage6_start_lua_synthetic_instance_object));
  *reinterpret_cast<uintptr_t*>(
      g_stage6_start_lua_synthetic_instance_control_block) =
      reinterpret_cast<uintptr_t>(kFallbackVtable);
  *reinterpret_cast<uint64_t*>(
      g_stage6_start_lua_synthetic_instance_control_block + 0x08) = 0x100000;
  *reinterpret_cast<uint64_t*>(
      g_stage6_start_lua_synthetic_instance_control_block + 0x10) = 0x100000;

  g_stage6_start_lua_synthetic_instance_vtable[0x40 / sizeof(uintptr_t)] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_synthetic_instance_slot40);
  g_stage6_start_lua_synthetic_instance_vtable[0x158 / sizeof(uintptr_t)] =
      reinterpret_cast<uintptr_t>(
          &mocktail_stage6_start_lua_synthetic_instance_slot158);

  g_stage6_start_lua_synthetic_instance_name[0] =
      static_cast<unsigned char>(8u << 1);
  std::memcpy(g_stage6_start_lua_synthetic_instance_name + 1, "Instance", 8);

  const uintptr_t object =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_synthetic_instance_object);
  *reinterpret_cast<uintptr_t*>(object + 0x00) =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_synthetic_instance_vtable);
  *reinterpret_cast<uintptr_t*>(object + 0xb0) =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_synthetic_instance_name);
  *reinterpret_cast<uintptr_t*>(object + 0x228) = source_value;

  char class_preview[64];
  ReadLibcxxStringPreview(ReadPointerIfReadable(object + 0xb0), class_preview,
                          sizeof(class_preview));
  char msg[760];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartLua synthetic Instance source prepared "
      "object=%p control=%p source=%p class='%s' reason=%s\n",
      reinterpret_cast<void*>(object),
      static_cast<void*>(g_stage6_start_lua_synthetic_instance_control_block),
      reinterpret_cast<void*>(source_value), class_preview,
      reason != nullptr ? reason : "");
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return object;
}

uintptr_t ResolveStage6StartLuaPrimary18SlotData(uintptr_t offset) {
  const uintptr_t base = g_stage6_start_lua_owner_slot_038;
  if (base < kStage5LowAddressThreshold) {
    return 0;
  }
  const uintptr_t slot = ReadPointerIfReadable(base + offset);
  return ReadPointerIfReadable(slot + 0x08);
}

extern "C" void* mocktail_stage6_start_lua_return_primary18_slot_data(
    void* self) {
  uintptr_t offset = 0x428;
  const char* slot = std::getenv("MOCKTAIL_STAGE6_START_LUA_RETURNER_SLOT");
  if (slot != nullptr) {
    if (std::strcmp(slot, "430") == 0 || std::strcmp(slot, "0x430") == 0) {
      offset = 0x430;
    } else if (std::strcmp(slot, "438") == 0 ||
               std::strcmp(slot, "0x438") == 0) {
      offset = 0x438;
    }
  }

  const uintptr_t result = ResolveStage6StartLuaPrimary18SlotData(offset);
  static volatile sig_atomic_t returner_logs = 0;
  if (returner_logs < 8) {
    char msg[560];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartLua synthetic target returner "
                 "self=%p slot=0x%lx result=%p result_fields{0=%p 8=%p 10=%p "
                 "18=%p 20=%p 28=%p}\n",
                 self, static_cast<unsigned long>(offset),
                 reinterpret_cast<void*>(result),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x00)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x08)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x10)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x18)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x20)),
                 reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x28)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++returner_logs;
  }
  return reinterpret_cast<void*>(result);
}

extern "C" void* mocktail_stage6_start_lua_return_self_1a0(void* self) {
  const uintptr_t target = reinterpret_cast<uintptr_t>(self);
  const uintptr_t result = ReadPointerIfReadable(target + 0x1a0);
  const uintptr_t result_vtable = ReadPointerIfReadable(result + 0x00);
  const uintptr_t result20 = ReadPointerIfReadable(result + 0x20);
  const bool result_looks_like_object =
      result >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(result + 0x28, sizeof(uintptr_t)) &&
      result_vtable >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(result_vtable, sizeof(uintptr_t));
  static volatile sig_atomic_t returner_logs = 0;
  if (returner_logs < 8) {
    char msg[1180];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua synthetic self+1a0 returner "
        "self=%p result=%p valid=%d self_fields{158=%p 1a0=%p 1b8=%p} "
        "result_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p} "
        "result20_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p}\n",
        self, reinterpret_cast<void*>(result), result_looks_like_object ? 1 : 0,
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1b8)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result + 0x28)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x00)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x08)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x10)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x18)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x20)),
        reinterpret_cast<void*>(ReadPointerIfReadable(result20 + 0x28)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++returner_logs;
  }
  if (!result_looks_like_object) {
    return nullptr;
  }
  return reinterpret_cast<void*>(result);
}

extern "C" void* mocktail_stage6_start_lua_return_size_40000(void* self) {
  static volatile sig_atomic_t returner_logs = 0;
  if (returner_logs < 8) {
    const uintptr_t target = reinterpret_cast<uintptr_t>(self);
    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua synthetic size returner "
        "self=%p result=0x40000 self_fields{158=%p 1a0=%p 1b8=%p}\n",
        self, reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x158)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
        reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1b8)));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++returner_logs;
  }
  return reinterpret_cast<void*>(0x40000);
}

uintptr_t InstallStage6StartLuaFallbackCallbackTarget(uintptr_t owner,
                                                      const char* reason) {
  if (!IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_FALLBACK_CALLBACK_TARGET") ||
      owner < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(owner + 0x3f8, sizeof(uintptr_t))) {
    return 0;
  }

  auto** slot = reinterpret_cast<void**>(owner + 0x3f8);
  if (*slot != nullptr &&
      IsReadableMemoryRange(reinterpret_cast<uintptr_t>(*slot),
                            sizeof(uintptr_t))) {
    return reinterpret_cast<uintptr_t>(*slot);
  }

  std::memset(g_stage6_start_lua_callback_target_vtable, 0,
              sizeof(g_stage6_start_lua_callback_target_vtable));
  std::memset(g_stage6_start_lua_callback_target_object, 0,
              sizeof(g_stage6_start_lua_callback_target_object));
  SeedStage6FakeIntrusiveRefcount(
      reinterpret_cast<unsigned char*>(
          g_stage6_start_lua_callback_target_object),
      sizeof(g_stage6_start_lua_callback_target_object));
  g_stage6_start_lua_callback_target_vtable[3] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_copy_empty_callback_table);
  g_stage6_start_lua_callback_target_vtable[6] =
      reinterpret_cast<uintptr_t>(&mocktail_stage6_start_lua_register_callback);
  g_stage6_start_lua_callback_target_vtable[8] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_slot8_callback_method);
  g_stage6_start_lua_callback_target_vtable[12] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_slot12_callback_method);
  g_stage6_start_lua_callback_target_vtable[13] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_slot13_callback_method);
  g_stage6_start_lua_callback_target_vtable[14] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_slot14_callback_method);
  g_stage6_start_lua_callback_target_vtable[15] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_slot15_callback_method);
  g_stage6_start_lua_callback_target_vtable[17] = reinterpret_cast<uintptr_t>(
      &mocktail_stage6_start_lua_send_app_event_callback);
  g_stage6_start_lua_callback_target_object[0] =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_target_vtable);
  g_stage6_start_lua_callback_target_object[1] = owner;

  if (!EnsureWritablePage(slot)) {
    char fail_msg[360];
    int fail_len = snprintf(
        fail_msg, sizeof(fail_msg),
        "  [patch] Stage6 StartLua fallback callback target mprotect failed "
        "owner=%p slot=%p errno=%d\n",
        reinterpret_cast<void*>(owner), static_cast<void*>(slot), errno);
    if (fail_len > 0) {
      write(2, fail_msg, static_cast<size_t>(fail_len));
    }
    return 0;
  }

  *slot = g_stage6_start_lua_callback_target_object;
  char msg[620];
  int len =
      snprintf(msg, sizeof(msg),
               "  [patch] installed Stage6 StartLua fallback callback target "
               "owner=%p slot=0x3f8 target=%p vtable=%p",
               reinterpret_cast<void*>(owner),
               static_cast<void*>(g_stage6_start_lua_callback_target_object),
               static_cast<void*>(g_stage6_start_lua_callback_target_vtable));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_target_object);
}

bool SeedStage6StartLuaDeepStateHeader(uintptr_t state, const char* reason);

uintptr_t InstallStage6StartLuaFallbackState(uintptr_t owner,
                                             uintptr_t configured_anchor,
                                             const char* reason) {
  if (IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_NULL_STATE") ||
      owner < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(owner + 0x418, sizeof(uintptr_t))) {
    return 0;
  }

  auto* state_slot = reinterpret_cast<uintptr_t*>(owner + 0x418);
  if (*state_slot != 0) {
    return *state_slot;
  }

  const char* state_source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_STATE_SOURCE");
  if (state_source != nullptr &&
      std::strcmp(state_source, "last_owner_state") == 0 &&
      g_stage6_last_app_bridge_owner_state >= kStage5LowAddressThreshold &&
      IsReadableMemoryRange(g_stage6_last_app_bridge_owner_state + 0x138,
                            sizeof(uint32_t))) {
    if (!EnsureWritablePage(state_slot)) {
      char fail_msg[400];
      int fail_len = snprintf(
          fail_msg, sizeof(fail_msg),
          "  [patch] Stage6 StartLua last-owner state mprotect failed "
          "owner=%p slot=%p source_owner=%p state=%p errno=%d\n",
          reinterpret_cast<void*>(owner), static_cast<void*>(state_slot),
          reinterpret_cast<void*>(g_stage6_last_app_bridge_owner),
          reinterpret_cast<void*>(g_stage6_last_app_bridge_owner_state), errno);
      if (fail_len > 0) {
        write(2, fail_msg, static_cast<size_t>(fail_len));
      }
      return 0;
    }

    *state_slot = g_stage6_last_app_bridge_owner_state;
    SeedStage6StartLuaDeepStateHeader(g_stage6_last_app_bridge_owner_state,
                                      "last-owner-state");
    char msg[620];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] installed Stage6 StartLua last-owner state "
                 "owner=%p slot=0x418 source_owner=%p state=%p reason=%s\n",
                 reinterpret_cast<void*>(owner),
                 reinterpret_cast<void*>(g_stage6_last_app_bridge_owner),
                 reinterpret_cast<void*>(g_stage6_last_app_bridge_owner_state),
                 reason != nullptr ? reason : "");
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    return g_stage6_last_app_bridge_owner_state;
  }

  std::memset(g_stage6_start_lua_state_scratch, 0,
              sizeof(g_stage6_start_lua_state_scratch));
  std::memset(g_stage6_start_lua_anchor_scratch, 0,
              sizeof(g_stage6_start_lua_anchor_scratch));
  std::memset(g_stage6_start_lua_callback_scratch, 0,
              sizeof(g_stage6_start_lua_callback_scratch));
  SeedStage6FakeIntrusiveRefcount(g_stage6_start_lua_callback_scratch,
                                  sizeof(g_stage6_start_lua_callback_scratch));
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch) = 1;
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch + 0x10) =
      0x7fffffffu;
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_callback_scratch) = 1;
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_anchor_scratch + 0x08) =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_scratch);
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_callback_scratch + 0x08) =
      reinterpret_cast<uintptr_t>(&mocktail_stage6_start_lua_noop_continuation);
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_state_scratch) =
      configured_anchor != 0
          ? configured_anchor
          : reinterpret_cast<uintptr_t>(g_stage6_start_lua_anchor_scratch);
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_state_scratch + 0x138) = 0;

  if (!EnsureWritablePage(state_slot)) {
    char fail_msg[360];
    int fail_len = snprintf(
        fail_msg, sizeof(fail_msg),
        "  [patch] Stage6 StartLua fallback state mprotect failed "
        "owner=%p slot=%p errno=%d\n",
        reinterpret_cast<void*>(owner), static_cast<void*>(state_slot), errno);
    if (fail_len > 0) {
      write(2, fail_msg, static_cast<size_t>(fail_len));
    }
    return 0;
  }

  const uintptr_t state =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_state_scratch);
  *state_slot = state;
  char msg[620];
  int len =
      snprintf(msg, sizeof(msg),
               "  [patch] installed Stage6 StartLua fallback state "
               "owner=%p slot=0x418 state=%p anchor=%p",
               reinterpret_cast<void*>(owner), reinterpret_cast<void*>(state),
               *reinterpret_cast<void**>(g_stage6_start_lua_state_scratch));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return state;
}

bool SeedStage6StartLuaGatePayload(uintptr_t payload, const char* reason) {
  if (IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_GATE_PAYLOAD") ||
      payload < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(payload, sizeof(uint64_t) + sizeof(uintptr_t))) {
    return false;
  }

  auto* count = reinterpret_cast<uint64_t*>(payload);
  const uintptr_t list = ReadPointerIfReadable(payload + 0x08);
  if (*count != 0 && list != 0) {
    return false;
  }
  if (!EnsureWritablePage(count)) {
    char fail_msg[360];
    int fail_len =
        snprintf(fail_msg, sizeof(fail_msg),
                 "  [patch] Stage6 StartLua gate payload mprotect failed "
                 "payload=%p errno=%d\n",
                 reinterpret_cast<void*>(payload), errno);
    if (fail_len > 0) {
      write(2, fail_msg, static_cast<size_t>(fail_len));
    }
    return false;
  }

  if (*count == 0) {
    *count = 1;
  }
  uintptr_t seeded_list = list;
  if (seeded_list == 0) {
    std::memset(g_stage6_start_lua_callback_scratch, 0,
                sizeof(g_stage6_start_lua_callback_scratch));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_callback_scratch,
        sizeof(g_stage6_start_lua_callback_scratch));
    *reinterpret_cast<uint32_t*>(g_stage6_start_lua_callback_scratch) = 1;
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_callback_scratch + 0x08) =
        reinterpret_cast<uintptr_t>(
            &mocktail_stage6_start_lua_noop_continuation);
    seeded_list =
        reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_scratch);
    *reinterpret_cast<uintptr_t*>(payload + 0x08) = seeded_list;
  }

  char msg[520];
  int len = snprintf(msg, sizeof(msg),
                     "  [patch] Stage6 StartLua gate payload seeded "
                     "payload=%p count=%llu list=%p",
                     reinterpret_cast<void*>(payload),
                     static_cast<unsigned long long>(*count),
                     reinterpret_cast<void*>(seeded_list));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return true;
}

bool SeedStage6StartLuaDeepStateHeader(uintptr_t state, const char* reason) {
  if (!IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_DEEP_STATE_HEADER") ||
      state < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(state, sizeof(uintptr_t))) {
    return false;
  }

  uintptr_t header = ReadPointerIfReadable(state + 0x00);
  if (header != 0 && ReadPointerIfReadable(header + 0x08) != 0) {
    return false;
  }

  std::memset(g_stage6_start_lua_anchor_scratch, 0,
              sizeof(g_stage6_start_lua_anchor_scratch));
  std::memset(g_stage6_start_lua_callback_scratch, 0,
              sizeof(g_stage6_start_lua_callback_scratch));
  SeedStage6FakeIntrusiveRefcount(g_stage6_start_lua_anchor_scratch,
                                  sizeof(g_stage6_start_lua_anchor_scratch));
  SeedStage6FakeIntrusiveRefcount(g_stage6_start_lua_callback_scratch,
                                  sizeof(g_stage6_start_lua_callback_scratch));
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch) = 1;
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_anchor_scratch + 0x10) =
      0x7fffffffu;
  *reinterpret_cast<uint32_t*>(g_stage6_start_lua_callback_scratch) = 1;
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_anchor_scratch + 0x08) =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_callback_scratch);
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_callback_scratch + 0x08) =
      reinterpret_cast<uintptr_t>(&mocktail_stage6_start_lua_noop_continuation);

  if (!EnsureWritablePage(reinterpret_cast<void*>(state))) {
    char fail_msg[420];
    int fail_len = snprintf(
        fail_msg, sizeof(fail_msg),
        "  [patch] Stage6 deep StartLua state header mprotect failed "
        "state=%p old_header=%p errno=%d\n",
        reinterpret_cast<void*>(state), reinterpret_cast<void*>(header), errno);
    if (fail_len > 0) {
      write(2, fail_msg, static_cast<size_t>(fail_len));
    }
    return false;
  }

  header = reinterpret_cast<uintptr_t>(g_stage6_start_lua_anchor_scratch);
  *reinterpret_cast<uintptr_t*>(state) = header;
  char msg[720];
  int len =
      snprintf(msg, sizeof(msg),
               "  [patch] Stage6 deep StartLua state header seeded "
               "state=%p header=%p header8=%p reason=%s\n",
               reinterpret_cast<void*>(state), reinterpret_cast<void*>(header),
               reinterpret_cast<void*>(ReadPointerIfReadable(header + 0x08)),
               reason != nullptr ? reason : "");
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return true;
}

bool SeedStage6StartLuaPrimaryFallbackState(uintptr_t owner,
                                            const char* reason) {
  if (IsDisabled("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FALLBACK_STATE") ||
      g_libroblox_base == 0 || owner < kStage5LowAddressThreshold) {
    return false;
  }

  const uintptr_t primary =
      g_libroblox_base + kStage6AppBridgePrimaryStateOffset;
  if (!IsReadableMemoryRange(primary, 0x20) ||
      !EnsureWritablePage(reinterpret_cast<void*>(primary))) {
    return false;
  }

  std::memset(g_stage6_start_lua_target_table_scratch, 0,
              sizeof(g_stage6_start_lua_target_table_scratch));
  std::memset(g_stage6_start_lua_refcount_vtable, 0,
              sizeof(g_stage6_start_lua_refcount_vtable));
  std::memset(g_stage6_start_lua_refcount_scratch, 0,
              sizeof(g_stage6_start_lua_refcount_scratch));
  SeedStage6FakeIntrusiveRefcount(
      g_stage6_start_lua_target_table_scratch,
      sizeof(g_stage6_start_lua_target_table_scratch));
  SeedStage6FakeIntrusiveRefcount(g_stage6_start_lua_refcount_scratch,
                                  sizeof(g_stage6_start_lua_refcount_scratch));
  SeedStage6StartLuaTargetTableScratchVtable();
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_refcount_scratch) =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_refcount_vtable);
  *reinterpret_cast<uint64_t*>(g_stage6_start_lua_refcount_scratch + 0x08) =
      0x100000;
  *reinterpret_cast<uint64_t*>(g_stage6_start_lua_refcount_scratch + 0x10) =
      0x100000;

  const uintptr_t primary_slot_8 =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_target_table_scratch);
  const uintptr_t primary_slot_10 =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_refcount_scratch);
  g_stage6_start_lua_owner_slot_028 = primary_slot_8;
  g_stage6_start_lua_owner_slot_030 = primary_slot_10;
  g_stage6_start_lua_owner_slot_038 = 0;
  *reinterpret_cast<uintptr_t*>(primary + 0x08) = primary_slot_8;
  *reinterpret_cast<uintptr_t*>(primary + 0x10) = primary_slot_10;
  *reinterpret_cast<uintptr_t*>(primary + 0x18) = 0;

  char msg[900];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartLua primary fallback state seeded "
      "primary=%p owner=%p fields{8=%p 10=%p 18=%p} refcounts{%llu/%llu}",
      reinterpret_cast<void*>(primary), reinterpret_cast<void*>(owner),
      reinterpret_cast<void*>(primary_slot_8),
      reinterpret_cast<void*>(primary_slot_10), static_cast<void*>(nullptr),
      static_cast<unsigned long long>(*reinterpret_cast<uint64_t*>(
          g_stage6_start_lua_refcount_scratch + 0x08)),
      static_cast<unsigned long long>(*reinterpret_cast<uint64_t*>(
          g_stage6_start_lua_refcount_scratch + 0x10)));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return true;
}

bool SeedStage6StartLuaPrimaryStateFromOwner(uintptr_t owner,
                                             const char* reason) {
  if (!IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER") ||
      g_libroblox_base == 0 || owner < kStage5LowAddressThreshold) {
    return false;
  }

  auto resolve_owner_source = [owner](const char* name,
                                      uintptr_t default_offset,
                                      uintptr_t* source_offset) -> uintptr_t {
    const char* value = std::getenv(name);
    if (value != nullptr && std::strcmp(value, "owner") == 0) {
      *source_offset = static_cast<uintptr_t>(-1);
      return owner;
    }
    const uintptr_t offset = GetEnvAddress(name, default_offset);
    *source_offset = offset;
    if (offset < 0x1000) {
      return ReadPointerIfReadable(owner + offset);
    }
    return offset;
  };

  uintptr_t primary_slot_8_source = 0;
  uintptr_t primary_slot_10_source = 0;
  uintptr_t primary_slot_18_source = 0;
  const uintptr_t primary_slot_8 =
      resolve_owner_source("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT8_SOURCE",
                           0x28, &primary_slot_8_source);
  const uintptr_t primary_slot_10 =
      resolve_owner_source("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT10_SOURCE",
                           0x30, &primary_slot_10_source);
  const uintptr_t primary_slot_18 =
      resolve_owner_source("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT18_SOURCE",
                           0x38, &primary_slot_18_source);
  if (primary_slot_8 == 0 || primary_slot_10 == 0) {
    return SeedStage6StartLuaPrimaryFallbackState(owner, reason);
  }

  const uintptr_t primary =
      g_libroblox_base + kStage6AppBridgePrimaryStateOffset;
  if (!IsReadableMemoryRange(primary, 0x20) ||
      !EnsureWritablePage(reinterpret_cast<void*>(primary))) {
    return false;
  }

  g_stage6_start_lua_owner_slot_028 = primary_slot_8;
  g_stage6_start_lua_owner_slot_030 = primary_slot_10;
  g_stage6_start_lua_owner_slot_038 = primary_slot_18;
  *reinterpret_cast<uintptr_t*>(primary + 0x08) = primary_slot_8;
  *reinterpret_cast<uintptr_t*>(primary + 0x10) = primary_slot_10;
  *reinterpret_cast<uintptr_t*>(primary + 0x18) = primary_slot_18;

  char msg[1200];
  int len =
      snprintf(msg, sizeof(msg),
               "  [patch] Stage6 StartLua primary state seeded from owner "
               "primary=%p owner=%p source{8=0x%lx 10=0x%lx 18=0x%lx} "
               "fields{8=%p 10=%p 18=%p} "
               "owner_tables{%p/%p %p/%p}",
               reinterpret_cast<void*>(primary), reinterpret_cast<void*>(owner),
               static_cast<unsigned long>(primary_slot_8_source),
               static_cast<unsigned long>(primary_slot_10_source),
               static_cast<unsigned long>(primary_slot_18_source),
               reinterpret_cast<void*>(primary_slot_8),
               reinterpret_cast<void*>(primary_slot_10),
               reinterpret_cast<void*>(primary_slot_18),
               reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x850)),
               reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x858)),
               reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x860)),
               reinterpret_cast<void*>(ReadPointerIfReadable(owner + 0x868)));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  if (reason != nullptr && reason[0] != '\0') {
    const char prefix[] = " reason=";
    write(2, prefix, sizeof(prefix) - 1);
    write(2, reason, std::strlen(reason));
  }
  const char newline[] = "\n";
  write(2, newline, sizeof(newline) - 1);
  return true;
}

uintptr_t ResolveStage6StartLuaTargetTableFallback(uintptr_t object) {
  const char* source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_SOURCE");
  if (source == nullptr || source[0] == '\0' ||
      std::strcmp(source, "object") == 0) {
    return object;
  }
  if (std::strcmp(source, "slot8") == 0) {
    return ReadPointerIfReadable(object + 0x08);
  }
  if (std::strcmp(source, "slot10") == 0) {
    return ReadPointerIfReadable(object + 0x10);
  }
  if (std::strcmp(source, "slot18") == 0) {
    return ReadPointerIfReadable(object + 0x18);
  }
  if (std::strcmp(source, "primary8") == 0 ||
      std::strcmp(source, "owner28") == 0) {
    return g_stage6_start_lua_owner_slot_028;
  }
  if (std::strcmp(source, "primary10") == 0 ||
      std::strcmp(source, "owner30") == 0) {
    return g_stage6_start_lua_owner_slot_030;
  }
  if (std::strcmp(source, "primary18") == 0 ||
      std::strcmp(source, "owner38") == 0) {
    return g_stage6_start_lua_owner_slot_038;
  }
  auto resolve_primary18_slot = [](uintptr_t offset,
                                   bool data_field) -> uintptr_t {
    const uintptr_t base = g_stage6_start_lua_owner_slot_038;
    if (base < kStage5LowAddressThreshold) {
      return 0;
    }
    const uintptr_t slot = ReadPointerIfReadable(base + offset);
    if (!data_field) {
      return slot;
    }
    return ReadPointerIfReadable(slot + 0x08);
  };
  if (std::strcmp(source, "primary18_slot428") == 0 ||
      std::strcmp(source, "owner38_slot428") == 0) {
    return resolve_primary18_slot(0x428, false);
  }
  if (std::strcmp(source, "primary18_slot430") == 0 ||
      std::strcmp(source, "owner38_slot430") == 0) {
    return resolve_primary18_slot(0x430, false);
  }
  if (std::strcmp(source, "primary18_slot438") == 0 ||
      std::strcmp(source, "owner38_slot438") == 0) {
    return resolve_primary18_slot(0x438, false);
  }
  if (std::strcmp(source, "primary18_slot428_data") == 0 ||
      std::strcmp(source, "owner38_slot428_data") == 0) {
    return resolve_primary18_slot(0x428, true);
  }
  if (std::strcmp(source, "primary18_slot430_data") == 0 ||
      std::strcmp(source, "owner38_slot430_data") == 0) {
    return resolve_primary18_slot(0x430, true);
  }
  if (std::strcmp(source, "primary18_slot438_data") == 0 ||
      std::strcmp(source, "owner38_slot438_data") == 0) {
    return resolve_primary18_slot(0x438, true);
  }
  if (std::strcmp(source, "return_primary18_slot_data") == 0 ||
      std::strcmp(source, "return_primary18_slot428_data") == 0) {
    std::memset(g_stage6_start_lua_returner_target_vtable, 0,
                sizeof(g_stage6_start_lua_returner_target_vtable));
    std::memset(g_stage6_start_lua_returner_target_object, 0,
                sizeof(g_stage6_start_lua_returner_target_object));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_returner_target_object,
        sizeof(g_stage6_start_lua_returner_target_object));
    g_stage6_start_lua_returner_target_vtable[6] = reinterpret_cast<uintptr_t>(
        &mocktail_stage6_start_lua_return_primary18_slot_data);
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object) =
        reinterpret_cast<uintptr_t>(g_stage6_start_lua_returner_target_vtable);
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object +
                                  0x20) =
        ReadPointerIfReadable(g_stage6_start_lua_owner_slot_038 + 0x428);
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object +
                                  0x28) = g_stage6_start_lua_owner_slot_038;
    return reinterpret_cast<uintptr_t>(
        g_stage6_start_lua_returner_target_object);
  }
  if (std::strcmp(source, "return_self_1a0") == 0 ||
      std::strcmp(source, "synthetic_self_1a0") == 0) {
    std::memset(g_stage6_start_lua_returner_target_vtable, 0,
                sizeof(g_stage6_start_lua_returner_target_vtable));
    std::memset(g_stage6_start_lua_returner_target_object, 0,
                sizeof(g_stage6_start_lua_returner_target_object));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_returner_target_object,
        sizeof(g_stage6_start_lua_returner_target_object));
    g_stage6_start_lua_returner_target_vtable[6] =
        reinterpret_cast<uintptr_t>(&mocktail_stage6_start_lua_return_self_1a0);
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object) =
        reinterpret_cast<uintptr_t>(g_stage6_start_lua_returner_target_vtable);
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object +
                                  0x08) = object;
    *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_returner_target_object +
                                  0x28) = g_stage6_start_lua_owner_slot_038;
    return reinterpret_cast<uintptr_t>(
        g_stage6_start_lua_returner_target_object);
  }
  const char* field_prefix = "field";
  const size_t field_prefix_len = std::strlen(field_prefix);
  if (std::strncmp(source, field_prefix, field_prefix_len) == 0) {
    const char* offset_text = source + field_prefix_len;
    char* end = nullptr;
    unsigned long long offset = std::strtoull(offset_text, &end, 0);
    if (end != offset_text && offset < 0x1000) {
      return ReadPointerIfReadable(object + static_cast<uintptr_t>(offset));
    }
  }
  if (std::strcmp(source, "scratch") == 0) {
    std::memset(g_stage6_start_lua_target_table_scratch, 0,
                sizeof(g_stage6_start_lua_target_table_scratch));
    SeedStage6FakeIntrusiveRefcount(
        g_stage6_start_lua_target_table_scratch,
        sizeof(g_stage6_start_lua_target_table_scratch));
    SeedStage6StartLuaTargetTableScratchVtable();
    return reinterpret_cast<uintptr_t>(g_stage6_start_lua_target_table_scratch);
  }
  char* end = nullptr;
  unsigned long long parsed = std::strtoull(source, &end, 0);
  if (end != source) {
    return static_cast<uintptr_t>(parsed);
  }
  return 0;
}

void LogStage6StartLuaTargetCandidates(uintptr_t object) {
  if (!IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_TARGET_CANDIDATES") ||
      object < kStage5LowAddressThreshold) {
    return;
  }

  static volatile sig_atomic_t candidate_logs = 0;
  if (candidate_logs >= 4) {
    return;
  }
  ++candidate_logs;

  constexpr uintptr_t kCandidateOffsets[] = {
      0x18,  0x20,  0x28,  0x30,  0x38,  0x40,  0x48,  0x50,  0x58,
      0x60,  0x68,  0x70,  0x78,  0x80,  0x88,  0x90,  0x98,  0xa0,
      0xa8,  0xb0,  0xb8,  0xc0,  0xc8,  0xd0,  0xd8,  0xe0,  0xe8,
      0xf0,  0xf8,  0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130,
      0x138, 0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
      0x180, 0x188, 0x190, 0x198, 0x1a0, 0x1a8, 0x1b0, 0x1b8, 0x1c0,
      0x248, 0x3f8, 0x418, 0x850, 0x858, 0x860, 0x868};

  char header[220];
  int header_len =
      snprintf(header, sizeof(header),
               "  [trace] Stage6 StartLua target candidate scan object=%p\n",
               reinterpret_cast<void*>(object));
  if (header_len > 0) {
    write(2, header, static_cast<size_t>(header_len));
  }

  for (uintptr_t offset : kCandidateOffsets) {
    const uintptr_t candidate = ReadPointerIfReadable(object + offset);
    if (candidate < kStage5LowAddressThreshold ||
        !IsReadableMemoryRange(candidate, 0x40)) {
      continue;
    }
    const uintptr_t vtable = ReadPointerIfReadable(candidate);
    const uintptr_t vtable30 = ReadPointerIfReadable(vtable + 0x30);
    const uintptr_t field_10 = ReadPointerIfReadable(candidate + 0x10);
    const uintptr_t field_18 = ReadPointerIfReadable(candidate + 0x18);
    const uintptr_t field_158 = ReadPointerIfReadable(candidate + 0x158);
    const uintptr_t field_1a0 = ReadPointerIfReadable(candidate + 0x1a0);
    char msg[780];
    int len = snprintf(
        msg, sizeof(msg),
        "  [trace] Stage6 StartLua target candidate offset=0x%lx "
        "value=%p fields{0=%p 10=%p 18=%p 158=%p 1a0=%p} vtable30=%p\n",
        static_cast<unsigned long>(offset), reinterpret_cast<void*>(candidate),
        reinterpret_cast<void*>(vtable), reinterpret_cast<void*>(field_10),
        reinterpret_cast<void*>(field_18), reinterpret_cast<void*>(field_158),
        reinterpret_cast<void*>(field_1a0), reinterpret_cast<void*>(vtable30));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }

  auto log_broad_scan = [](const char* label, uintptr_t base_object) {
    if (!IsEnabled("MOCKTAIL_TRACE_STAGE6_START_LUA_TARGET_BROAD_SCAN") ||
        g_libroblox_base == 0 || base_object < kStage5LowAddressThreshold) {
      return;
    }

    int logged = 0;
    for (uintptr_t offset = 0; offset < 0x1000 && logged < 32; offset += 8) {
      const uintptr_t candidate = ReadPointerIfReadable(base_object + offset);
      if (candidate < kStage5LowAddressThreshold ||
          !IsReadableMemoryRange(candidate, 0x40)) {
        continue;
      }
      const uintptr_t vtable = ReadPointerIfReadable(candidate);
      const uintptr_t vtable30 = ReadPointerIfReadable(vtable + 0x30);
      if (vtable30 < g_libroblox_base + kLibrobloxTextStartOffset ||
          vtable30 >= g_libroblox_base + kLibrobloxExecutableSegmentEndOffset) {
        continue;
      }
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua broad target candidate %s+0x%lx "
          "value=%p vtable=%p vtable30=%p/off=0x%lx "
          "fields{8=%p 10=%p 18=%p 20=%p 28=%p 158=%p 1a0=%p}\n",
          label, static_cast<unsigned long>(offset),
          reinterpret_cast<void*>(candidate), reinterpret_cast<void*>(vtable),
          reinterpret_cast<void*>(vtable30),
          static_cast<unsigned long>(vtable30 - g_libroblox_base),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x20)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x28)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x158)),
          reinterpret_cast<void*>(ReadPointerIfReadable(candidate + 0x1a0)));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
      ++logged;
    }
  };

  log_broad_scan("object", object);

  const uintptr_t primary18 = g_stage6_start_lua_owner_slot_038;
  if (primary18 >= kStage5LowAddressThreshold) {
    log_broad_scan("primary18", primary18);
    constexpr uintptr_t kPrimary18Slots[] = {0x428, 0x430, 0x438};
    for (uintptr_t offset : kPrimary18Slots) {
      const uintptr_t slot = ReadPointerIfReadable(primary18 + offset);
      const uintptr_t data = ReadPointerIfReadable(slot + 0x08);
      const uintptr_t slot_vtable = ReadPointerIfReadable(slot);
      const uintptr_t slot_vtable30 = ReadPointerIfReadable(slot_vtable + 0x30);
      const uintptr_t data_vtable = ReadPointerIfReadable(data);
      const uintptr_t data_vtable30 = ReadPointerIfReadable(data_vtable + 0x30);
      char msg[980];
      int len = snprintf(
          msg, sizeof(msg),
          "  [trace] Stage6 StartLua primary18 slot offset=0x%lx "
          "slot=%p slot_fields{0=%p 8=%p 10=%p 18=%p 1a0=%p} "
          "slot_vtable30=%p data=%p data_fields{0=%p 8=%p 10=%p 18=%p "
          "1a0=%p} data_vtable30=%p\n",
          static_cast<unsigned long>(offset), reinterpret_cast<void*>(slot),
          reinterpret_cast<void*>(slot_vtable),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(slot + 0x1a0)),
          reinterpret_cast<void*>(slot_vtable30), reinterpret_cast<void*>(data),
          reinterpret_cast<void*>(data_vtable),
          reinterpret_cast<void*>(ReadPointerIfReadable(data + 0x08)),
          reinterpret_cast<void*>(ReadPointerIfReadable(data + 0x10)),
          reinterpret_cast<void*>(ReadPointerIfReadable(data + 0x18)),
          reinterpret_cast<void*>(ReadPointerIfReadable(data + 0x1a0)),
          reinterpret_cast<void*>(data_vtable30));
      if (len > 0) {
        write(2, msg, static_cast<size_t>(len));
      }
    }
  }
}

uintptr_t ResolveStage6StartLuaTargetTableFallbackRefcount(uintptr_t object,
                                                           uintptr_t target) {
  const char* source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_REF_SOURCE");
  if (source == nullptr || source[0] == '\0' ||
      std::strcmp(source, "target10") == 0) {
    return ReadPointerIfReadable(target + 0x10);
  }
  if (std::strcmp(source, "object10") == 0) {
    return ReadPointerIfReadable(object + 0x10);
  }
  if (std::strcmp(source, "primary10") == 0) {
    return g_stage6_start_lua_owner_slot_030;
  }
  if (std::strcmp(source, "zero") == 0) {
    return 0;
  }
  char* end = nullptr;
  unsigned long long parsed = std::strtoull(source, &end, 0);
  if (end != source) {
    return static_cast<uintptr_t>(parsed);
  }
  return 0;
}

bool SeedStage6StartLuaTargetTableFallback(uintptr_t object, uint32_t index) {
  if (!IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_TABLE") ||
      object < kStage5LowAddressThreshold || index > 16) {
    return false;
  }

  const uintptr_t pair = object + 0x850 + static_cast<uintptr_t>(index) * 0x10;
  if (!IsReadableMemoryRange(pair, sizeof(uintptr_t) * 2)) {
    return false;
  }
  if (ReadPointerIfReadable(pair) != 0) {
    return false;
  }

  const uintptr_t target = ResolveStage6StartLuaTargetTableFallback(object);
  if (target < kStage5LowAddressThreshold) {
    return false;
  }
  if (!IsReadableMemoryRange(target + 0x1a0, 0x40)) {
    char unreadable_msg[420];
    int unreadable_len = snprintf(
        unreadable_msg, sizeof(unreadable_msg),
        "  [patch] Stage6 StartLua target-table fallback target unreadable "
        "object=%p index=%u target=%p\n",
        reinterpret_cast<void*>(object), index,
        reinterpret_cast<void*>(target));
    if (unreadable_len > 0) {
      write(2, unreadable_msg, static_cast<size_t>(unreadable_len));
    }
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(pair))) {
    return false;
  }

  uintptr_t refcount =
      ResolveStage6StartLuaTargetTableFallbackRefcount(object, target);
  if (refcount != 0 &&
      !IsReadableMemoryRange(refcount + 0x10, sizeof(uint64_t))) {
    refcount = 0;
  }
  uint64_t refcount_old_8 = 0;
  uint64_t refcount_old_10 = 0;
  if (refcount != 0 &&
      IsReadableMemoryRange(refcount + 0x10, sizeof(uint64_t))) {
    refcount_old_8 = *reinterpret_cast<const uint64_t*>(refcount + 0x08);
    refcount_old_10 = *reinterpret_cast<const uint64_t*>(refcount + 0x10);
    __atomic_add_fetch(reinterpret_cast<uint64_t*>(refcount + 0x08), 1,
                       __ATOMIC_RELAXED);
  }

  *reinterpret_cast<uintptr_t*>(pair) = target;
  *reinterpret_cast<uintptr_t*>(pair + 0x08) = refcount;
  const char* source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_SOURCE");
  const char* ref_source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_REF_SOURCE");
  char msg[1320];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartLua target-table fallback seeded "
      "object=%p index=%u pair=%p target=%p ref=%p source=%s "
      "ref_source=%s refcounts_old{%llu/%llu} "
      "target_fields{0=%p 8=%p 10=%p 18=%p 158=%p 1a0=%p 1b8=%p}\n",
      reinterpret_cast<void*>(object), index, reinterpret_cast<void*>(pair),
      reinterpret_cast<void*>(target), reinterpret_cast<void*>(refcount),
      (source != nullptr && source[0] != '\0') ? source : "object",
      (ref_source != nullptr && ref_source[0] != '\0') ? ref_source
                                                       : "target10",
      static_cast<unsigned long long>(refcount_old_8),
      static_cast<unsigned long long>(refcount_old_10),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x08)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x10)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x18)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x158)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1a0)),
      reinterpret_cast<void*>(ReadPointerIfReadable(target + 0x1b8)));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return true;
}

bool ForceNativeFlagsLoadedForTaskScheduler(const char* reason) {
  if (g_libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_NATIVE_FLAGS_LOADED")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      g_libroblox_base + kRobloxNativeFlagsLoadedByteOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] native flags-loaded byte is unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(flag)) {
    std::cerr << "  [patch] native flags-loaded byte mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }
  const unsigned int old_value = *flag;
  *flag = 1;
  std::cout << "  [patch] native flags-loaded byte forced at 0x" << std::hex
            << kRobloxNativeFlagsLoadedByteOffset << std::dec
            << " old=" << old_value;
  if (reason != nullptr && reason[0] != '\0') {
    std::cout << " reason=" << reason;
  }
  std::cout << '\n' << std::flush;
  return true;
}

bool ForceStage6DataModelPatcherForceLocalFlag(const char* reason) {
  if (g_libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_DATAMODEL_FORCE_LOCAL")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      g_libroblox_base + kStage6DataModelPatcherForceLocalFlagOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] DataModelPatcherForceLocal flag is unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(flag)) {
    std::cerr << "  [patch] DataModelPatcherForceLocal flag mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  const unsigned int old_value = *flag;
  *flag = static_cast<unsigned char>(*flag | 0x01);
  __builtin___clear_cache(reinterpret_cast<char*>(flag),
                          reinterpret_cast<char*>(flag) + sizeof(*flag));
  std::cout << "  [patch] DataModelPatcherForceLocal flag forced at 0x"
            << std::hex << kStage6DataModelPatcherForceLocalFlagOffset
            << std::dec << " old=" << old_value
            << " new=" << static_cast<unsigned int>(*flag);
  if (reason != nullptr && reason[0] != '\0') {
    std::cout << " reason=" << reason;
  }
  std::cout << '\n' << std::flush;
  return true;
}

bool ForceStage6DeferRbxmSignatureCheckToPostTtiFlag(const char* reason) {
  if (g_libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_DEFER_RBXM_SIGNATURE_CHECK_TO_POST_TTI")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      g_libroblox_base + kStage6DeferRbxmSignatureCheckToPostTtiFlagOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] DeferRbxmSignatureCheckToPostTti flag is "
              << "unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(flag)) {
    std::cerr
        << "  [patch] DeferRbxmSignatureCheckToPostTti flag mprotect failed: "
        << std::strerror(errno) << '\n'
        << std::flush;
    return false;
  }

  const unsigned int old_value = *flag;
  *flag = static_cast<unsigned char>(*flag | 0x01);
  __builtin___clear_cache(reinterpret_cast<char*>(flag),
                          reinterpret_cast<char*>(flag) + sizeof(*flag));
  std::cout << "  [patch] DeferRbxmSignatureCheckToPostTti flag forced at 0x"
            << std::hex << kStage6DeferRbxmSignatureCheckToPostTtiFlagOffset
            << std::dec << " old=" << old_value
            << " new=" << static_cast<unsigned int>(*flag);
  if (reason != nullptr && reason[0] != '\0') {
    std::cout << " reason=" << reason;
  }
  std::cout << '\n' << std::flush;
  return true;
}

bool ForceStage6StartLuaSelfReferenceCallbackFlag(const char* reason) {
  if (g_libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_PATCH_STAGE6_START_LUA_SELF_REFERENCE_CALLBACK")) {
    return false;
  }

  auto* flag = reinterpret_cast<unsigned char*>(
      g_libroblox_base + kStage6StartLuaSelfReferenceCallbackFlagOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(flag),
                             sizeof(*flag))) {
    std::cerr << "  [patch] Stage6 StartLua self-reference callback flag is "
              << "unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(flag)) {
    std::cerr << "  [patch] Stage6 StartLua self-reference callback flag "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  const unsigned int old_value = *flag;
  *flag = static_cast<unsigned char>(*flag | 0x01);
  std::cout << "  [patch] Stage6 StartLua self-reference callback flag "
            << "forced at 0x" << std::hex
            << kStage6StartLuaSelfReferenceCallbackFlagOffset << std::dec
            << " old=" << old_value;
  if (reason != nullptr && reason[0] != '\0') {
    std::cout << " reason=" << reason;
  }
  std::cout << '\n' << std::flush;
  return true;
}

}  // namespace mocktail::legacy::internal
