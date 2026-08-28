#include <SDL3/SDL_video.h>
#include <arpa/inet.h>
#include <asm/prctl.h>
#include <dlfcn.h>
#include <elf.h>
#include <execinfo.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "compat/bionic_abi_exports.h"
#include "compat/bionic_prctl_runtime.h"
#include "compat/bionic_pthread_create_runtime.h"
#include "compat/bionic_socket_runtime.h"
#include "compat/build_profile.h"
#include "compat/elf_build_id.h"
#include "compat/host_abi_experiment.h"
#include "compat/host_abi_profile.h"
#include "compat/host_allocator_bridge.h"
#include "jnivm/jnivm.h"
#include "legacy/bionic_runtime_wrappers.h"
#include "legacy/engine_startup_types.h"
#include "legacy/headless_signal_helpers.h"
#include "legacy/headless_signal_state.h"
#include "legacy/legacy_runtime.h"
#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/rbxm_diagnostics.h"
#include "legacy/runtime_adapters.h"
#include "legacy/runtime_environment.h"
#include "legacy/runtime_paths.h"
#include "legacy/stage6_offsets.h"
#include "legacy/stage6_rbxm_fallbacks.h"
#include "legacy/stage6_runtime.h"
#include "legacy/stage6_signal_recovery.h"
#include "legacy/stage6_start_lua_fallbacks.h"
#include "legacy/symbol_resolver.h"
#include "libc_shim/libc_shim.h"
#include "linker/linker.h"
#include "mocktail/graphics/bionic_egl_bridge.h"
#include "runtime/discord_rpc.h"
#include "runtime/environment.h"
#include "runtime/jnivm_platform_web_callbacks.h"
#include "runtime/owned_pthread.h"
#include "runtime/platform_cache_migration.h"
#include "runtime/roblox_app_lifecycle.h"
#include "runtime/roblox_capability_resolver.h"
#include "runtime/roblox_experience_composition.h"
#include "runtime/roblox_game_session_native_adapter.h"
#include "runtime/roblox_platform_web_symbols.h"
#include "runtime/roblox_text_input_jni_bridge.h"
#include "runtime/roblox_window_input_runtime.h"
#include "runtime/runtime_config.h"
#include "runtime/runtime_paths.h"
#include "services/client_settings_service.h"
#include "services/http_client.h"
#include "window/window.h"
#include "window/window_game_surface_bridge.h"

#ifdef MOCKTAIL_USE_BIONIC_LINKER
#include <mcpelauncher/linker.h>
#endif

#ifndef MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST
#define MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST \
  "config/roblox_compatibility.json"
#endif

namespace mocktail::legacy::internal {

alignas(16) unsigned char g_stage6_start_game_map_entry_scratch[0x900];
alignas(16) unsigned char g_stage6_start_game_empty_item_scratch[0x100];

void PrintStage(int stage, const char* description) {
  g_current_stage = stage;
  if (stage != 5) {
    g_stage5_last_fallback_rip = 0;
  }
  std::cout << "[stage " << stage << "] " << description << '\n' << std::flush;
}

void PrintBacktraceNoSig(const char* prefix) {
  void* frames[64];
  int frame_count = backtrace(frames, 64);
  if (frame_count <= 0) {
    return;
  }

  char** symbols = backtrace_symbols(frames, frame_count);
  if (!symbols) {
    return;
  }

  write(2, prefix, std::strlen(prefix));
  for (int i = 0; i < frame_count; ++i) {
    size_t written = 0;
    if (symbols[i] != nullptr) {
      written = std::strlen(symbols[i]);
      write(2, symbols[i], written);
    }
    if (i + 1 < frame_count) {
      write(2, "\n", 1);
    }
  }
  write(2, "\n", 1);
  free(symbols);
}

void ReadRbxmFileManagerCacheRegistryPreview(uintptr_t libroblox_base,
                                             char* out, size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (libroblox_base == 0) {
    std::snprintf(out, out_size, "enabled_cache_fields{base=null}");
    return;
  }

  const uintptr_t registry =
      libroblox_base + kStage6RbxmFileManagerCacheRegistryGlobalOffset;
  char memory_preview[180];
  ReadMemoryHexPreview(registry, memory_preview, sizeof(memory_preview));
  std::snprintf(
      out, out_size,
      "enabled_cache_fields{base=%p 0=%p 8=0x%lx 10=0x%lx 18=0x%lx "
      "20=0x%lx 28=0x%lx 30=0x%lx preview=\"%s\"}",
      reinterpret_cast<void*>(registry),
      reinterpret_cast<void*>(ReadPointerIfReadable(registry + 0x00)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x08)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x10)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x18)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x20)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x28)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x30)),
      memory_preview);
}

void ReadRbxmFileManagerFeatureRegistryPreview(uintptr_t libroblox_base,
                                               char* out, size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (libroblox_base == 0) {
    std::snprintf(out, out_size, "feature_cache_fields{base=null}");
    return;
  }

  const uintptr_t registry =
      libroblox_base + kStage6RbxmFileManagerFeatureRegistryGlobalOffset;
  const uintptr_t node = ReadPointerIfReadable(registry + 0x10);
  char memory_preview[180];
  char node_key_preview[160];
  ReadMemoryHexPreview(registry, memory_preview, sizeof(memory_preview));
  ReadLibcxxStringPreview(node + 0x10, node_key_preview,
                          sizeof(node_key_preview));
  const unsigned int flag28 =
      IsReadableMemoryRange(node + 0x28, 1)
          ? *reinterpret_cast<unsigned char*>(node + 0x28)
          : 0xffu;
  const unsigned int flag29 =
      IsReadableMemoryRange(node + 0x29, 1)
          ? *reinterpret_cast<unsigned char*>(node + 0x29)
          : 0xffu;
  const unsigned int flag2a =
      IsReadableMemoryRange(node + 0x2a, 1)
          ? *reinterpret_cast<unsigned char*>(node + 0x2a)
          : 0xffu;
  std::snprintf(
      out, out_size,
      "feature_cache_fields{base=%p 0=%p 8=0x%lx 10=0x%lx 18=0x%lx "
      "20=0x%lx node=%p node_hash=0x%lx node_key=\"%s\" "
      "node_flags{28=0x%x 29=0x%x 2a=0x%x} preview=\"%s\"}",
      reinterpret_cast<void*>(registry),
      reinterpret_cast<void*>(ReadPointerIfReadable(registry + 0x00)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x08)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x10)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x18)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x20)),
      reinterpret_cast<void*>(node),
      static_cast<unsigned long>(ReadPointerIfReadable(node + 0x08)),
      node_key_preview, flag28, flag29, flag2a, memory_preview);
}

void ReadRbxmCoreClassRegistryPreview(uintptr_t libroblox_base, char* out,
                                      size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (libroblox_base == 0) {
    std::snprintf(out, out_size, "rbxm-core-class-registry{base=null}");
    return;
  }

  const uintptr_t registry =
      libroblox_base + kStage6RbxmCoreClassRegistryGlobalOffset;
  char memory_preview[180];
  ReadMemoryHexPreview(registry, memory_preview, sizeof(memory_preview));
  std::snprintf(
      out, out_size,
      "rbxm-core-class-registry{base=%p 0=%p 8=0x%lx 10=0x%lx "
      "18=0x%lx 20=0x%lx 28=0x%lx 30=0x%lx preview=\"%s\"}",
      reinterpret_cast<void*>(registry),
      reinterpret_cast<void*>(ReadPointerIfReadable(registry + 0x00)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x08)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x10)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x18)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x20)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x28)),
      static_cast<unsigned long>(ReadPointerIfReadable(registry + 0x30)),
      memory_preview);
}

size_t CountRbxmDescriptorRegistryNodes(uintptr_t head, size_t max_nodes) {
  size_t count = 0;
  uintptr_t node = head;
  while (node != 0 && count < max_nodes &&
         IsReadableMemoryRange(node, sizeof(uintptr_t) * 2)) {
    ++count;
    const uintptr_t next = ReadPointerIfReadable(node + sizeof(uintptr_t));
    if (next == node) {
      break;
    }
    node = next;
  }
  return count;
}

void ReadRbxmDescriptorNameCandidate(uintptr_t descriptor, char* out,
                                     size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (!IsReadableMemoryRange(descriptor + 0x08, sizeof(uintptr_t))) {
    return;
  }

  const uintptr_t name_object = ReadPointerIfReadable(descriptor + 0x08);
  ReadLibcxxStringPreview(name_object, out, out_size);
}

void ReadRbxmDescriptorRegistryNodePreview(uintptr_t head, char* out,
                                           size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  size_t pos = 0;
  int written = std::snprintf(out, out_size, "registry_node_preview[");
  if (written <= 0) {
    return;
  }
  pos = std::min(static_cast<size_t>(written), out_size - 1);

  uintptr_t node = head;
  for (size_t index = 0; index < 4 && node != 0; ++index) {
    if (!IsReadableMemoryRange(node, sizeof(uintptr_t) * 8)) {
      written = std::snprintf(
          out + pos, out_size - pos, "%s{index=%zu node=%p unreadable}",
          index == 0 ? "" : " ", index, reinterpret_cast<void*>(node));
      if (written > 0) {
        pos = std::min(pos + static_cast<size_t>(written), out_size - 1);
      }
      break;
    }

    const uintptr_t field00 = ReadPointerIfReadable(node + 0x00);
    const uintptr_t field08 = ReadPointerIfReadable(node + 0x08);
    const uintptr_t field10 = ReadPointerIfReadable(node + 0x10);
    const uintptr_t field18 = ReadPointerIfReadable(node + 0x18);
    const uintptr_t field20 = ReadPointerIfReadable(node + 0x20);
    const uintptr_t field28 = ReadPointerIfReadable(node + 0x28);
    const uintptr_t field30 = ReadPointerIfReadable(node + 0x30);
    const uintptr_t field38 = ReadPointerIfReadable(node + 0x38);
    char node_plus_10_descriptor_name[96];
    char node_plus_18_descriptor_name[96];
    char node_plus_20_descriptor_name[96];
    char node_plus_28_descriptor_name[96];
    char node_plus_30_descriptor_name[96];
    char node_plus_38_descriptor_name[96];
    char node_preview[96];
    ReadRbxmDescriptorNameCandidate(field10, node_plus_10_descriptor_name,
                                    sizeof(node_plus_10_descriptor_name));
    ReadRbxmDescriptorNameCandidate(field18, node_plus_18_descriptor_name,
                                    sizeof(node_plus_18_descriptor_name));
    ReadRbxmDescriptorNameCandidate(field20, node_plus_20_descriptor_name,
                                    sizeof(node_plus_20_descriptor_name));
    ReadRbxmDescriptorNameCandidate(field28, node_plus_28_descriptor_name,
                                    sizeof(node_plus_28_descriptor_name));
    ReadRbxmDescriptorNameCandidate(field30, node_plus_30_descriptor_name,
                                    sizeof(node_plus_30_descriptor_name));
    ReadRbxmDescriptorNameCandidate(field38, node_plus_38_descriptor_name,
                                    sizeof(node_plus_38_descriptor_name));
    ReadMemoryHexPreview(node, node_preview, sizeof(node_preview));
    written = std::snprintf(
        out + pos, out_size - pos,
        "%s{index=%zu node=%p 0=%p 8=%p 10=%p 18=%p 20=%p 28=%p "
        "30=%p 38=%p descriptor10_name=\"%s\" descriptor18_name=\"%s\" "
        "descriptor20_name=\"%s\" descriptor28_name=\"%s\" "
        "descriptor30_name=\"%s\" descriptor38_name=\"%s\" raw=\"%s\"}",
        index == 0 ? "" : " ", index, reinterpret_cast<void*>(node),
        reinterpret_cast<void*>(field00), reinterpret_cast<void*>(field08),
        reinterpret_cast<void*>(field10), reinterpret_cast<void*>(field18),
        reinterpret_cast<void*>(field20), reinterpret_cast<void*>(field28),
        reinterpret_cast<void*>(field30), reinterpret_cast<void*>(field38),
        node_plus_10_descriptor_name, node_plus_18_descriptor_name,
        node_plus_20_descriptor_name, node_plus_28_descriptor_name,
        node_plus_30_descriptor_name, node_plus_38_descriptor_name,
        node_preview);
    if (written <= 0) {
      break;
    }
    pos = std::min(pos + static_cast<size_t>(written), out_size - 1);
    if (field08 == node) {
      break;
    }
    node = field08;
  }

  if (pos < out_size - 1) {
    std::snprintf(out + pos, out_size - pos, "]");
  } else {
    out[out_size - 1] = '\0';
  }
}

void ReadRbxmDescriptorRegistryPreview(uintptr_t libroblox_base, char* out,
                                       size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  out[0] = '\0';
  if (libroblox_base == 0) {
    std::snprintf(out, out_size, "rbxm-descriptor-registry{base=null}");
    return;
  }

  const uintptr_t primary_global =
      libroblox_base + kStage6RbxmPrimaryDescriptorRegistryHeadGlobalOffset;
  const uintptr_t secondary_global =
      libroblox_base + kStage6RbxmSecondaryDescriptorRegistryHeadGlobalOffset;
  const uintptr_t property_global =
      libroblox_base + kStage6RbxmPropertyDescriptorRegistryHeadGlobalOffset;
  const uintptr_t primary_head = ReadPointerIfReadable(primary_global);
  const uintptr_t secondary_head = ReadPointerIfReadable(secondary_global);
  const uintptr_t property_head = ReadPointerIfReadable(property_global);
  char property_global_preview[96];
  char primary_nodes_preview[1200];
  char secondary_nodes_preview[1200];
  char property_nodes_preview[1200];
  ReadMemoryHexPreview(property_global, property_global_preview,
                       sizeof(property_global_preview));
  ReadRbxmDescriptorRegistryNodePreview(primary_head, primary_nodes_preview,
                                        sizeof(primary_nodes_preview));
  ReadRbxmDescriptorRegistryNodePreview(secondary_head, secondary_nodes_preview,
                                        sizeof(secondary_nodes_preview));
  ReadRbxmDescriptorRegistryNodePreview(property_head, property_nodes_preview,
                                        sizeof(property_nodes_preview));
  std::snprintf(
      out, out_size,
      "rbxm-descriptor-registry{"
      "primary_descriptor_registry{global=%p head=%p count=%zu "
      "first_value=%p first_next=%p nodes=%s} "
      "secondary_descriptor_registry{global=%p head=%p count=%zu "
      "first_value=%p first_next=%p nodes=%s} "
      "property_descriptor_registry{global=%p head=%p count=%zu "
      "first_value=%p first_next=%p nodes=%s preview=\"%s\"}}",
      reinterpret_cast<void*>(primary_global),
      reinterpret_cast<void*>(primary_head),
      CountRbxmDescriptorRegistryNodes(primary_head, 4096),
      reinterpret_cast<void*>(ReadPointerIfReadable(primary_head + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(primary_head + 0x08)),
      primary_nodes_preview, reinterpret_cast<void*>(secondary_global),
      reinterpret_cast<void*>(secondary_head),
      CountRbxmDescriptorRegistryNodes(secondary_head, 4096),
      reinterpret_cast<void*>(ReadPointerIfReadable(secondary_head + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(secondary_head + 0x08)),
      secondary_nodes_preview, reinterpret_cast<void*>(property_global),
      reinterpret_cast<void*>(property_head),
      CountRbxmDescriptorRegistryNodes(property_head, 4096),
      reinterpret_cast<void*>(ReadPointerIfReadable(property_head + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(property_head + 0x08)),
      property_nodes_preview, property_global_preview);
}

bool TryRecoverStage6StartLuaTargetTableDynamicCastTypeInfo(
    ucontext_t* ucontext, uintptr_t libroblox_offset) {
  if (ucontext == nullptr ||
      libroblox_offset != kStage6StartLuaTargetTableDynamicCastTypeReadOffset) {
    return false;
  }

  const uintptr_t object =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
  const uintptr_t scratch_begin =
      reinterpret_cast<uintptr_t>(g_stage6_start_lua_target_table_scratch);
  const uintptr_t scratch_end =
      scratch_begin + sizeof(g_stage6_start_lua_target_table_scratch);
  if (object < scratch_begin || object >= scratch_end) {
    return false;
  }

  const uintptr_t target_type_info =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
  if (!IsLikelyUserPointer(target_type_info) ||
      !IsReadableMemoryRange(target_type_info + 0x08, sizeof(uintptr_t))) {
    return false;
  }

  const uintptr_t previous_type_info =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
  const uintptr_t type_name = ReadPointerIfReadable(target_type_info + 0x08);
  ucontext->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(target_type_info);

  static volatile sig_atomic_t recover_logs = 0;
  if (recover_logs < 16) {
    char msg[620];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] recovered Stage6 StartLua target-table dynamic-cast "
        "type-info object=%p previous_type_info=%p target_type_info=%p "
        "type_name=%p\n",
        reinterpret_cast<void*>(object),
        reinterpret_cast<void*>(previous_type_info),
        reinterpret_cast<void*>(target_type_info),
        reinterpret_cast<void*>(type_name));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
    ++recover_logs;
  }
  return true;
}

void DumpStage6AppBridgeStaticState(const char* label) {
  if (!IsEnabled("MOCKTAIL_DUMP_STAGE6_APP_BRIDGE_STATE") &&
      !IsEnabled("MOCKTAIL_DUMP_APP_BRIDGE_STATIC_STATE")) {
    return;
  }
  const uintptr_t base = static_cast<uintptr_t>(g_libroblox_base);
  if (base == 0) {
    return;
  }

  auto dump_object = [&](const char* name, uintptr_t offset) {
    const uintptr_t object = base + offset;
    const uintptr_t slot_08 = ReadPointerIfReadable(object + 0x08);
    const uintptr_t slot_10 = ReadPointerIfReadable(object + 0x10);
    std::cout << "  [trace] Stage6 AppBridge static "
              << (label ? label : "state") << ' ' << name
              << " object=" << reinterpret_cast<void*>(object) << " fields{0="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x00))
              << " 8=" << reinterpret_cast<void*>(slot_08)
              << " 10=" << reinterpret_cast<void*>(slot_10) << " 18="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x18))
              << " 20="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x20))
              << " 28="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x28))
              << " 30="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x30))
              << " 2c0="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x2c0))
              << " 2c8="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x2c8))
              << " 2d0="
              << reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x2d0))
              << "}\n";
    if (slot_10 != 0) {
      std::cout
          << "  [trace] Stage6 AppBridge static " << (label ? label : "state")
          << ' ' << name << ".slot10 fields{0="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x00))
          << " 8="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x08))
          << " 10="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x10))
          << " 18="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x18))
          << " 20="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x20))
          << " 28="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x28))
          << " 30="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x30))
          << " 38="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_10 + 0x38))
          << "}\n";
    }
    if (slot_08 != 0) {
      std::cout
          << "  [trace] Stage6 AppBridge static " << (label ? label : "state")
          << ' ' << name << ".slot8 fields{0="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x00))
          << " 8="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x08))
          << " 10="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x10))
          << " 18="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x18))
          << " 20="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x20))
          << " 28="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x28))
          << " 30="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x30))
          << " 38="
          << reinterpret_cast<void*>(ReadPointerIfReadable(slot_08 + 0x38))
          << "}\n";
    }
  };

  dump_object("primary", kStage6AppBridgePrimaryStateOffset);
  dump_object("secondary", kStage6AppBridgeSecondaryStateOffset);
  std::cout << std::flush;
}

bool ShouldPatchStage6StartGameOwnerGameState() {
  if (IsDisabled("MOCKTAIL_PATCH_STAGE6_START_GAME_OWNER_GAME_STATE")) {
    return false;
  }
  return IsEnabled("MOCKTAIL_PATCH_STAGE6_START_GAME_OWNER_GAME_STATE") ||
         IsEnabled("MOCKTAIL_START_GAME_WITH_PARAM");
}

uintptr_t PrepareStage6StartGameMapEntryScratch(const char* reason) {
  std::memset(g_stage6_start_game_map_entry_scratch, 0,
              sizeof(g_stage6_start_game_map_entry_scratch));
  const uintptr_t entry =
      reinterpret_cast<uintptr_t>(g_stage6_start_game_map_entry_scratch);
  *reinterpret_cast<uint64_t*>(entry + 0x58) = kStage6FakeIntrusiveRefcount;
  *reinterpret_cast<uint64_t*>(entry + 0x60) = kStage6FakeIntrusiveRefcount - 1;
  *reinterpret_cast<uint64_t*>(entry + 0x68) = kStage6FakeIntrusiveRefcount;
  *reinterpret_cast<uint64_t*>(entry + 0xb8) = kStage6FakeIntrusiveRefcount;

  char msg[520];
  int len = snprintf(
      msg, sizeof(msg),
      "  [patch] prepared Stage6 StartGame map-entry scratch "
      "entry=%p fields{18=%p 58=0x%llx 60=0x%llx 68=0x%llx b0=%u b8=0x%llx} "
      "reason=%s\n",
      reinterpret_cast<void*>(entry),
      reinterpret_cast<void*>(ReadPointerIfReadable(entry + 0x18)),
      static_cast<unsigned long long>(
          *reinterpret_cast<uint64_t*>(entry + 0x58)),
      static_cast<unsigned long long>(
          *reinterpret_cast<uint64_t*>(entry + 0x60)),
      static_cast<unsigned long long>(
          *reinterpret_cast<uint64_t*>(entry + 0x68)),
      static_cast<unsigned int>(
          *reinterpret_cast<unsigned char*>(entry + 0xb0)),
      static_cast<unsigned long long>(
          *reinterpret_cast<uint64_t*>(entry + 0xb8)),
      reason != nullptr ? reason : "");
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return entry;
}

uintptr_t PrepareStage6StartGameEmptyItemScratch(const char* reason) {
  std::memset(g_stage6_start_game_empty_item_scratch, 0,
              sizeof(g_stage6_start_game_empty_item_scratch));
  const uintptr_t item =
      reinterpret_cast<uintptr_t>(g_stage6_start_game_empty_item_scratch);
  char msg[360];
  int len =
      snprintf(msg, sizeof(msg),
               "  [patch] prepared Stage6 StartGame empty item scratch "
               "item=%p fields{78=%p 80=%p} reason=%s\n",
               reinterpret_cast<void*>(item),
               reinterpret_cast<void*>(ReadPointerIfReadable(item + 0x78)),
               reinterpret_cast<void*>(ReadPointerIfReadable(item + 0x80)),
               reason != nullptr ? reason : "");
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
  return item;
}

bool ResetStage6AppBridgeStaticGuards(const char* reason) {
  if (g_libroblox_base == 0 ||
      !IsEnabled("MOCKTAIL_RESET_STAGE6_APP_BRIDGE_STATIC_GUARDS")) {
    return false;
  }

  const uintptr_t base = static_cast<uintptr_t>(g_libroblox_base);
  auto reset_guard = [&](const char* name, uintptr_t offset) -> bool {
    auto* guard = reinterpret_cast<unsigned char*>(base + offset);
    if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(guard),
                               sizeof(*guard)) ||
        !EnsureWritablePage(guard)) {
      return false;
    }
    const unsigned int old_value = *guard;
    *guard = 0;
    std::cout << "  [patch] Stage6 AppBridge " << name
              << " init guard reset at 0x" << std::hex << offset << std::dec
              << " old=" << old_value;
    if (reason != nullptr && reason[0] != '\0') {
      std::cout << " reason=" << reason;
    }
    std::cout << '\n' << std::flush;
    return true;
  };

  bool reset = false;
  reset |= reset_guard("primary", kStage6AppBridgePrimaryInitGuardOffset);
  reset |= reset_guard("secondary", kStage6AppBridgeSecondaryInitGuardOffset);
  return reset;
}

bool UnwindStage6StartLuaSetupFrame(ucontext_t* ucontext) {
  if (ucontext == nullptr) {
    return false;
  }
  const uintptr_t rbp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
  if (!IsReadableMemoryRange(rbp - 0x28, 0x38)) {
    return false;
  }

  ucontext->uc_mcontext.gregs[REG_R15] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x08));
  ucontext->uc_mcontext.gregs[REG_R14] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x10));
  ucontext->uc_mcontext.gregs[REG_R13] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x18));
  ucontext->uc_mcontext.gregs[REG_R12] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x20));
  ucontext->uc_mcontext.gregs[REG_RBX] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x28));
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
      *reinterpret_cast<const uintptr_t*>(rbp + sizeof(uintptr_t)));
  ucontext->uc_mcontext.gregs[REG_RSP] =
      static_cast<greg_t>(rbp + sizeof(uintptr_t) * 2);
  ucontext->uc_mcontext.gregs[REG_RBP] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp));
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;
  return true;
}

bool TryReturnFromDecodedRbpFrame(ucontext_t* uc,
                                  const unsigned char* instruction,
                                  uintptr_t code_base, uintptr_t return_value) {
  if (uc == nullptr || instruction == nullptr || code_base == 0) {
    return false;
  }

  const uintptr_t instruction_address =
      reinterpret_cast<uintptr_t>(instruction);
  if (instruction_address < code_base) {
    return false;
  }

  const uintptr_t scan_limit = 0x180;
  const uintptr_t scan_start =
      instruction_address -
      std::min(instruction_address - code_base, scan_limit);
  const unsigned char* prologue = nullptr;
  for (uintptr_t address = instruction_address; address > scan_start + 3;
       --address) {
    const auto* candidate = reinterpret_cast<const unsigned char*>(address - 4);
    if (candidate[0] == 0x55 && candidate[1] == 0x48 && candidate[2] == 0x89 &&
        candidate[3] == 0xe5) {
      prologue = candidate;
      break;
    }
  }
  if (prologue == nullptr) {
    return false;
  }

  int saved_regs[8];
  int saved_reg_count = 0;
  const unsigned char* pc = prologue + 4;
  while (pc < instruction && saved_reg_count < 8) {
    if (pc[0] == 0x53) {
      saved_regs[saved_reg_count++] = REG_RBX;
      pc += 1;
      continue;
    }
    if (pc + 1 < instruction && pc[0] == 0x41 && pc[1] >= 0x54 &&
        pc[1] <= 0x57) {
      saved_regs[saved_reg_count++] = pc[1] == 0x54   ? REG_R12
                                      : pc[1] == 0x55 ? REG_R13
                                      : pc[1] == 0x56 ? REG_R14
                                                      : REG_R15;
      pc += 2;
      continue;
    }
    if (pc + 3 < instruction && pc[0] == 0x48 && pc[1] == 0x83 &&
        pc[2] == 0xec) {
      pc += 4;
      continue;
    }
    if (pc + 6 < instruction && pc[0] == 0x48 && pc[1] == 0x81 &&
        pc[2] == 0xec) {
      pc += 7;
      continue;
    }
    if (pc[0] == 0x90) {
      pc += 1;
      continue;
    }
    break;
  }

  const uintptr_t rbp = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RBP]);
  const uintptr_t saved_area_size =
      static_cast<uintptr_t>(saved_reg_count) * sizeof(uintptr_t);
  if (rbp < 0x1000 || (rbp & 7) != 0 || rbp < saved_area_size) {
    return false;
  }
  if (!IsReadableMemoryRange(rbp - saved_area_size,
                             saved_area_size + sizeof(uintptr_t) * 2)) {
    return false;
  }

  const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
  const uintptr_t saved_rbp = frame[0];
  const uintptr_t return_address = frame[1];
  if (!IsLikelyUserPointer(return_address)) {
    return false;
  }

  for (int i = 0; i < saved_reg_count; ++i) {
    const uintptr_t saved_value =
        *reinterpret_cast<const uintptr_t*>(rbp - (i + 1) * sizeof(uintptr_t));
    uc->uc_mcontext.gregs[saved_regs[i]] = static_cast<greg_t>(saved_value);
  }
  uc->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(saved_rbp);
  uc->uc_mcontext.gregs[REG_RSP] =
      static_cast<greg_t>(rbp + sizeof(uintptr_t) * 2);
  uc->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(return_value);
  uc->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(return_address);
  return true;
}

void PrintContextBacktrace(ucontext_t* uc, const char* prefix) {
  if (uc == nullptr) {
    return;
  }

  uintptr_t rbp = static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RBP]);
  for (int i = 0; i < 32; ++i) {
    if (rbp < 0x1000 || (rbp & 7) != 0) {
      return;
    }
    if (!IsReadableMemoryRange(rbp, sizeof(uintptr_t) * 2)) {
      return;
    }

    auto* frame = reinterpret_cast<uintptr_t*>(rbp);
    uintptr_t next_rbp = 0;
    uintptr_t ret_addr = 0;
    if (__builtin_add_overflow_p((uintptr_t)frame, sizeof(uintptr_t),
                                 (uintptr_t)0) ||
        __builtin_add_overflow_p((uintptr_t)(frame + 1), sizeof(uintptr_t),
                                 (uintptr_t)0)) {
      return;
    }
    next_rbp = frame[0];
    ret_addr = frame[1];
    if (ret_addr == 0 || next_rbp == 0 || next_rbp <= rbp) {
      return;
    }

    char line[320];
    Dl_info dlinfo;
    const char* module_name = "(unknown)";
    const char* symbol_name = "(unknown)";
    if (dladdr(reinterpret_cast<void*>(ret_addr), &dlinfo) != 0) {
      if (dlinfo.dli_fname != nullptr && dlinfo.dli_fname[0] != '\0') {
        module_name = dlinfo.dli_fname;
      }
      if (dlinfo.dli_sname != nullptr && dlinfo.dli_sname[0] != '\0') {
        symbol_name = dlinfo.dli_sname;
      }
    }

    int len = std::snprintf(
        line, sizeof(line),
        "%s#%02d rbp=0x%016llx ret=0x%016llx symbol=%s in %s\n", prefix, i,
        static_cast<unsigned long long>(rbp),
        static_cast<unsigned long long>(ret_addr), symbol_name, module_name);
    write(2, line, static_cast<size_t>(len));

    rbp = next_rbp;
  }
}

void PrintAddressMapForRip(uintptr_t address) {
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }

  char buffer[262144];
  ssize_t bytes = 0;
  while (static_cast<size_t>(bytes) < sizeof(buffer) - 1) {
    ssize_t chunk = read(fd, buffer + bytes, sizeof(buffer) - 1 - bytes);
    if (chunk < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(fd);
      return;
    }
    if (chunk == 0) {
      break;
    }
    bytes += chunk;
  }
  close(fd);
  if (bytes <= 0) {
    return;
  }
  buffer[bytes] = '\0';

  const char* line = buffer;
  while (*line != '\0') {
    const char* line_end = std::strchr(line, '\n');
    if (line_end == nullptr) {
      line_end = buffer + bytes;
    }
    const char* dash = static_cast<const char*>(
        std::memchr(line, '-', static_cast<size_t>(line_end - line)));
    const char* space = static_cast<const char*>(
        std::memchr(line, ' ', static_cast<size_t>(line_end - line)));
    if (dash == nullptr || space == nullptr) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    char* endptr = nullptr;
    uintptr_t start = static_cast<uintptr_t>(std::strtoull(line, &endptr, 16));
    if (endptr == nullptr || endptr != dash) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    endptr = nullptr;
    uintptr_t end =
        static_cast<uintptr_t>(std::strtoull(dash + 1, &endptr, 16));
    if (endptr == nullptr || endptr != space || end <= start) {
      line = (*line_end == '\n') ? line_end + 1 : line_end;
      continue;
    }

    if (address >= start && address < end) {
      const char map_prefix[] = "  [crash] map:";
      write(2, map_prefix, sizeof(map_prefix) - 1);
      write(2, " ", 1);
      write(2, line, static_cast<size_t>(line_end - line));
      write(2, "\n", 1);
      return;
    }
    line = (*line_end == '\n') ? line_end + 1 : line_end;
  }
}

void LogStage6StartAppNonCodeTargetDetail(ucontext_t* ucontext) {
  if (ucontext == nullptr) {
    return;
  }
  const uintptr_t rip =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
  const uintptr_t base = static_cast<uintptr_t>(g_libroblox_base);
  const bool rip_is_libroblox_text =
      base != 0 && rip >= base + kLibrobloxTextStartOffset &&
      rip < base + kLibrobloxExecutableSegmentEndOffset;
  if (rip_is_libroblox_text) {
    return;
  }

  static volatile sig_atomic_t detail_logs = 0;
  if (detail_logs >= 16) {
    return;
  }
  ++detail_logs;

  const uintptr_t rax =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
  const uintptr_t rbx =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
  const uintptr_t rbp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
  const uintptr_t rcx =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
  const uintptr_t r13 =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R13]);
  const uintptr_t r15 =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_R15]);
  const uintptr_t rsp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
  const uintptr_t stack0 = ReadPointerIfReadable(rsp + 0x00);
  const uintptr_t stack1 = ReadPointerIfReadable(rsp + 0x08);
  const uintptr_t stack2 = ReadPointerIfReadable(rsp + 0x10);
  const uintptr_t caller_return = ReadPointerIfReadable(rbp + 0x08);
  const uintptr_t caller_offset =
      (base != 0 && caller_return >= base) ? caller_return - base : 0;
  const uintptr_t rip_delta_r13 = (rip >= r13) ? rip - r13 : 0;
  const uintptr_t rip_delta_rcx = (rip >= rcx) ? rip - rcx : 0;
  const uintptr_t rip_delta_rbx = (rip >= rbx) ? rip - rbx : 0;

  char source_preview[72];
  size_t preview_len = 0;
  while (preview_len + 1 < sizeof(source_preview) &&
         IsReadableMemoryRange(r15 + preview_len, 1)) {
    unsigned char ch =
        *reinterpret_cast<const unsigned char*>(r15 + preview_len);
    if (ch == '\0') {
      break;
    }
    source_preview[preview_len++] =
        std::isprint(ch) != 0 ? static_cast<char>(ch) : '.';
  }
  source_preview[preview_len] = '\0';

  char msg[1800];
  int len = std::snprintf(
      msg, sizeof(msg),
      "  [patch] Stage6 StartApp non-code target detail rip=%p "
      "rax=%p rbx=%p rbp=%p rcx=%p r13=%p r15=%p "
      "caller_return=%p/off=0x%lx source_preview=\"%s\" "
      "rip_delta{r13=0x%lx rcx=0x%lx rbx=0x%lx} "
      "stack{0=%p 1=%p 2=%p} "
      "r13_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p} "
      "rcx_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p} "
      "rbx_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p 30=%p}\n",
      reinterpret_cast<void*>(rip), reinterpret_cast<void*>(rax),
      reinterpret_cast<void*>(rbx), reinterpret_cast<void*>(rbp),
      reinterpret_cast<void*>(rcx), reinterpret_cast<void*>(r13),
      reinterpret_cast<void*>(r15), reinterpret_cast<void*>(caller_return),
      static_cast<unsigned long>(caller_offset), source_preview,
      static_cast<unsigned long>(rip_delta_r13),
      static_cast<unsigned long>(rip_delta_rcx),
      static_cast<unsigned long>(rip_delta_rbx),
      reinterpret_cast<void*>(stack0), reinterpret_cast<void*>(stack1),
      reinterpret_cast<void*>(stack2),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x08)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x10)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x18)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x20)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x28)),
      reinterpret_cast<void*>(ReadPointerIfReadable(r13 + 0x30)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x08)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x10)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x18)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x20)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x28)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rcx + 0x30)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x00)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x08)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x10)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x18)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x20)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x28)),
      reinterpret_cast<void*>(ReadPointerIfReadable(rbx + 0x30)));
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }

  PrintAddressMapForRip(rip);
  PrintAddressMapForRip(r13);
  PrintAddressMapForRip(rcx);
  PrintAddressMapForRip(rbx);
  PrintAddressMapForRip(rax);
}

bool IsUnsafeSoftTimeoutModule(void* rip) {
  Dl_info dlinfo;
  if (rip == nullptr || dladdr(rip, &dlinfo) == 0 ||
      dlinfo.dli_fname == nullptr) {
    return true;
  }
  const char* module = dlinfo.dli_fname;
  return std::strstr(module, "libc.so") != nullptr ||
         std::strstr(module, "libpthread.so") != nullptr ||
         std::strstr(module, "ld-linux") != nullptr ||
         std::strstr(module, "libstdc++") != nullptr ||
         std::strstr(module, "libgcc_s") != nullptr;
}

void JniOnLoadTimeoutAlarm(int, siginfo_t* info, void* context) {
  static_cast<void>(info);
  auto* uc = static_cast<ucontext_t*>(context);
  auto rip = uc ? static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]) : 0;
  auto rsp = uc ? static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RSP]) : 0;
  auto rbp = uc ? static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RBP]) : 0;
  auto rax = uc ? static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RAX]) : 0;
  char regs_msg[192];
  int len =
      std::snprintf(regs_msg, sizeof(regs_msg),
                    "  [timeout] RIP=0x%016llx RSP=0x%016llx RBP=0x%016llx "
                    "RAX=0x%016llx\n",
                    static_cast<unsigned long long>(rip),
                    static_cast<unsigned long long>(rsp),
                    static_cast<unsigned long long>(rbp),
                    static_cast<unsigned long long>(rax));
  write(2, regs_msg, static_cast<size_t>(len));

  if (g_jni_onload_in_progress == 0 || g_jni_onload_timings_printed != 0) {
    return;
  }
  g_jni_onload_timings_printed = 1;

  const char prefix[] =
      "  [timeout] JNI_OnLoad still in progress; stack snapshot:\n";
  write(2, prefix, sizeof(prefix) - 1);
  PrintContextBacktrace(uc, "    ");
  PrintBacktraceNoSig("    ");
  if (g_jni_onload_soft_timeout != 0 && g_jni_onload_jmp_armed != 0 &&
      !IsUnsafeSoftTimeoutModule(reinterpret_cast<void*>(rip))) {
    g_jni_onload_jmp_armed = 0;
    g_jni_onload_in_progress = 0;
    siglongjmp(g_jni_onload_jmp_buf, 1);
    return;
  }
  if (g_jni_onload_soft_timeout != 0 && g_jni_onload_jmp_armed != 0) {
    const char skip_msg[] =
        "  [timeout] soft timeout skipped for unsafe module; waiting\n";
    write(2, skip_msg, sizeof(skip_msg) - 1);
    return;
  }
  _exit(124);
}

void LibRobloxConstructorAlarm(int signo, siginfo_t* info, void* context) {
  static_cast<void>(info);
#if defined(__x86_64__)
  auto* uc = static_cast<ucontext_t*>(context);
  if (g_libroblox_ctor_recovery_in_progress != 0) {
    g_libroblox_ctor_recovery_in_progress = 0;
    g_libroblox_ctor_recovered_signo = signo;
    g_libroblox_ctor_recovered_rip =
        uc != nullptr ? static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP])
                      : 0;
    g_libroblox_ctor_recovered_si_addr = 0;
    siglongjmp(g_libroblox_ctor_jmp_buf, 1);
  }
#else
  (void)signo;
  (void)context;
#endif
}

void InstallLibRobloxConstructorAlarm() {
  struct sigaction action;
  std::memset(&action, 0, sizeof(action));
  action.sa_sigaction = LibRobloxConstructorAlarm;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigaction(SIGALRM, &action, nullptr);
}

void DisarmLibRobloxConstructorAlarm() {
  itimerval timer{};
  setitimer(ITIMER_REAL, &timer, nullptr);
}

void ArmLibRobloxConstructorAlarm() {
  int timeout_ms = GetEnvInt("MOCKTAIL_LIBROBLOX_CTOR_TIMEOUT_MS", 1000);
  if (timeout_ms <= 0) {
    return;
  }

  itimerval timer{};
  timer.it_value.tv_sec = timeout_ms / 1000;
  timer.it_value.tv_usec = (timeout_ms % 1000) * 1000;
  if (timer.it_value.tv_sec == 0 && timer.it_value.tv_usec == 0) {
    timer.it_value.tv_usec = 1000;
  }
  setitimer(ITIMER_REAL, &timer, nullptr);
}

void PublishCurrentJniEnv(JNIEnv* env) {
  using SetCurrentJniEnvFn = void (*)(void*);
  auto* set_current_jni_env = reinterpret_cast<SetCurrentJniEnvFn>(
      ::dlsym(RTLD_DEFAULT, "mocktail_set_current_jni_env"));
  if (set_current_jni_env) {
    set_current_jni_env(env);
  }
}

}  // namespace mocktail::legacy::internal
