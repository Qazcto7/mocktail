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
#include "legacy/legacy_runtime.h"
#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/rbxm_diagnostics.h"
#include "legacy/runtime_adapters.h"
#include "legacy/runtime_environment.h"
#include "legacy/runtime_paths.h"
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

#include "legacy/legacy_runtime_core.h"
#include "legacy/stage6_patches.h"

namespace mocktail::legacy::internal {

struct SavedCodePatch {
  uintptr_t offset = 0;
  unsigned char bytes[16] = {};
  size_t size = 0;
  bool saved = false;
  bool restored = false;
};
SavedCodePatch g_constructor_emutls_helper_patches[] = {
    {0x2c178d0, {}, 4, false, false},
    {0x2c18d80, {}, 4, false, false},
};

bool EngineTraceEnabled() { return IsEnabled("MOCKTAIL_ENGINE_TRACE"); }

void PreloadPthreadSymbols() {
  using PreloadPthreadSymbolsFn = void (*)();
  auto* preload_pthread_symbols = reinterpret_cast<PreloadPthreadSymbolsFn>(
      ::dlsym(RTLD_DEFAULT, "mocktail_preload_pthread_symbols"));
  if (preload_pthread_symbols) {
    preload_pthread_symbols();
  }
}

void EngineLog(const char* message) {
  if (EngineTraceEnabled()) {
    std::cerr << "  [engine] " << message << '\n';
  }
}

void EngineLogPtr(const char* name, const void* ptr) {
  if (EngineTraceEnabled()) {
    std::cerr << "  [engine] " << name << "=0x" << std::hex
              << reinterpret_cast<uintptr_t>(ptr) << std::dec << '\n';
  }
}

void PrintStepDecision(const char* name, bool enabled) {
  if (!VerboseOutputEnabled()) {
    return;
  }
  std::cout << "  [engine] " << (enabled ? "run  " : "skip ") << name << '\n'
            << std::flush;
}

void PrintNativeBypass(const char* name, const char* flag) {
  if (!VerboseOutputEnabled()) {
    return;
  }
  std::cout << "  [engine] bypass native " << name << " (set " << flag
            << "=1 to call Roblox entrypoint)\n"
            << std::flush;
}

bool PatchCode(void* address, const unsigned char* bytes, size_t size) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0 || !address || !bytes || size == 0) {
    return false;
  }
  uintptr_t start = reinterpret_cast<uintptr_t>(address);
  uintptr_t page = start & ~(static_cast<uintptr_t>(page_size) - 1);
  uintptr_t end = start + size;
  uintptr_t page_end = (end + static_cast<uintptr_t>(page_size) - 1) &
                       ~(static_cast<uintptr_t>(page_size) - 1);
  size_t protect_size = page_end - page;
  if (mprotect(reinterpret_cast<void*>(page), protect_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    return false;
  }
  std::memcpy(address, bytes, size);
  __builtin___clear_cache(reinterpret_cast<char*>(address),
                          reinterpret_cast<char*>(address) + size);
  return mprotect(reinterpret_cast<void*>(page), protect_size,
                  PROT_READ | PROT_EXEC) == 0;
}

extern "C" void* mocktail_emutls_get_bridge(void* key_ptr);

bool SaveOriginalConstructorEmutlsHelper(uintptr_t libroblox_base,
                                         uintptr_t offset) {
  for (auto& patch : g_constructor_emutls_helper_patches) {
    if (patch.offset != offset) {
      continue;
    }
    if (patch.saved) {
      return true;
    }
    if (patch.size == 0 || patch.size > sizeof(patch.bytes)) {
      return false;
    }
    auto* address =
        reinterpret_cast<const unsigned char*>(libroblox_base + offset);
    std::memcpy(patch.bytes, address, patch.size);
    patch.saved = true;
    patch.restored = false;
    return true;
  }
  return false;
}

bool RestoreConstructorEmutlsHelpers(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsEnabled("MOCKTAIL_KEEP_CONSTRUCTOR_EMUTLS_HELPERS_PATCHED")) {
    return false;
  }

  bool restored_any = false;
  bool restored_all = true;
  for (auto& patch : g_constructor_emutls_helper_patches) {
    if (!patch.saved || patch.restored) {
      continue;
    }
    bool restored =
        PatchCode(reinterpret_cast<void*>(libroblox_base + patch.offset),
                  patch.bytes, patch.size);
    patch.restored = restored;
    restored_any = restored_any || restored;
    restored_all = restored_all && restored;
    std::cout << "  [patch] constructor helper 0x" << std::hex << patch.offset
              << std::dec << (restored ? " restored" : " restore failed")
              << '\n'
              << std::flush;
  }
  return restored_any && restored_all;
}

bool RestoreRobloxEmutlsKey(uintptr_t libroblox_base, uintptr_t offset,
                            uint64_t size, uint64_t align) {
  if (libroblox_base == 0 || size == 0 || align == 0) {
    return false;
  }
  auto* key = reinterpret_cast<uint64_t*>(libroblox_base + offset);
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    return false;
  }
  uintptr_t page = reinterpret_cast<uintptr_t>(key) &
                   ~(static_cast<uintptr_t>(page_size) - 1);
  if (mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(page_size),
               PROT_READ | PROT_WRITE) != 0) {
    std::cerr << "  [patch] emutls key 0x" << std::hex << offset << std::dec
              << " restore mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }
  key[0] = size;
  key[1] = align;
  key[2] = 0;
  key[3] = 0;
  std::cout << "  [patch] emutls key 0x" << std::hex << offset << std::dec
            << " restored size=0x" << std::hex << size << " align=0x" << align
            << std::dec << '\n'
            << std::flush;
  return true;
}

void RestoreKnownRobloxEmutlsKeys(uintptr_t libroblox_base) {
  if (IsDisabled("MOCKTAIL_RESTORE_KNOWN_EMUTLS_KEYS")) {
    return;
  }
  RestoreRobloxEmutlsKey(libroblox_base, 0x7022d40, 0x420, 0x20);
  RestoreRobloxEmutlsKey(libroblox_base, 0x7022d60, 0x1, 0x1);
  RestoreRobloxEmutlsKey(libroblox_base, 0x7068498, 0x8, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x70684b8, 0x238, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x70684f8, 0x8, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x7069a00, 0x20, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x706d1c8, 0x8, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x706d1e8, 0x8, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x706d208, 0x1, 0x1);
  RestoreRobloxEmutlsKey(libroblox_base, 0x706d228, 0x10, 0x8);
  RestoreRobloxEmutlsKey(libroblox_base, 0x706d390, 0x20, 0x1);
}

bool PatchRobloxEmutlsGetBridge(uintptr_t libroblox_base) {
  if (libroblox_base == 0 || IsDisabled("MOCKTAIL_PATCH_EMUTLS_GET_BRIDGE")) {
    return false;
  }
  if (!IsEnabled("MOCKTAIL_PATCH_EMUTLS_GET_BRIDGE") &&
      !IsEnabled("MOCKTAIL_RUN_LIBROBLOX_CTORS")) {
    return false;
  }
  constexpr uintptr_t kEmutlsGetOffset = 0x2c18d80;
  unsigned char patch[12] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t bridge = reinterpret_cast<uintptr_t>(&mocktail_emutls_get_bridge);
  std::memcpy(patch + 2, &bridge, sizeof(bridge));
  bool patched =
      PatchCode(reinterpret_cast<void*>(libroblox_base + kEmutlsGetOffset),
                patch, sizeof(patch));
  std::cout << "  [patch] emutls_get bridge "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

void DumpLibcxxStringGlobal(uintptr_t libroblox_base, uintptr_t offset,
                            const char* name) {
  if (libroblox_base == 0 || name == nullptr) {
    return;
  }
  auto* data = reinterpret_cast<const unsigned char*>(libroblox_base + offset);
  const bool is_long = (data[0] & 1u) != 0;
  size_t length = 0;
  const char* chars = nullptr;
  if (is_long) {
    auto* words = reinterpret_cast<const uintptr_t*>(data);
    length = static_cast<size_t>(words[1]);
    chars = reinterpret_cast<const char*>(words[2]);
  } else {
    length = data[0] >> 1;
    chars = reinterpret_cast<const char*>(data + 1);
  }
  if (chars == nullptr || length > 256) {
    std::cout << "  [dbg] " << name << " off=0x" << std::hex << offset
              << std::dec << " invalid length=" << length << " long=" << is_long
              << '\n'
              << std::flush;
    return;
  }
  std::cout << "  [dbg] " << name << " off=0x" << std::hex << offset << std::dec
            << " long=" << is_long << " len=" << length
            << " value=" << std::string(chars, length) << '\n'
            << std::flush;
}

void DumpLibcxxStringAt(uintptr_t address, const char* name) {
  if (address == 0 || name == nullptr) {
    return;
  }
  auto* data = reinterpret_cast<const unsigned char*>(address);
  const bool is_long = (data[0] & 1u) != 0;
  size_t length = 0;
  const char* chars = nullptr;
  if (is_long) {
    auto* words = reinterpret_cast<const uintptr_t*>(data);
    length = static_cast<size_t>(words[1]);
    chars = reinterpret_cast<const char*>(words[2]);
  } else {
    length = data[0] >> 1;
    chars = reinterpret_cast<const char*>(data + 1);
  }
  if (chars == nullptr || length > 256) {
    std::cout << "  [dbg] " << name << " ptr=0x" << std::hex << address
              << std::dec << " invalid length=" << length << " long=" << is_long
              << '\n'
              << std::flush;
    return;
  }
  std::cout << "  [dbg] " << name << " ptr=0x" << std::hex << address
            << std::dec << " long=" << is_long << " len=" << length
            << " value=" << std::string(chars, length) << '\n'
            << std::flush;
}

void DumpLibcxxStringPointerGlobal(uintptr_t libroblox_base, uintptr_t offset,
                                   const char* name) {
  if (libroblox_base == 0 || name == nullptr) {
    return;
  }
  uintptr_t target =
      *reinterpret_cast<const uintptr_t*>(libroblox_base + offset);
  std::cout << "  [dbg] " << name << " off=0x" << std::hex << offset
            << " pointer=0x" << target << std::dec << '\n'
            << std::flush;
  DumpLibcxxStringAt(target, name);
}

void DumpRobloxUrlGlobals(const char* label) {
  if (!IsEnabled("MOCKTAIL_DUMP_URL_GLOBALS") || g_libroblox_base == 0) {
    return;
  }
  std::cout << "  [dbg] URL globals " << (label ? label : "") << '\n'
            << std::flush;
  DumpLibcxxStringGlobal(g_libroblox_base, 0x73cff38, "settings_hash_or_host");
  DumpLibcxxStringGlobal(g_libroblox_base, 0x73f22b0, "url_global_73f22b0");
  DumpLibcxxStringGlobal(g_libroblox_base, 0x73f8958, "channel_global");
  DumpLibcxxStringGlobal(g_libroblox_base, 0x73f8960, "base_url_owner");
  DumpLibcxxStringGlobal(g_libroblox_base, 0x73f8968, "base_url_global");
  DumpLibcxxStringPointerGlobal(g_libroblox_base, 0x73f8960,
                                "base_url_owner_target");
  DumpLibcxxStringPointerGlobal(g_libroblox_base, 0x73f8968,
                                "base_url_global_target");
}

void WriteLibcxxString(void* out, const std::string& value) {
  if (out == nullptr) {
    return;
  }
  auto* bytes = reinterpret_cast<unsigned char*>(out);
  std::memset(bytes, 0, 24);
  if (value.size() <= 22) {
    bytes[0] = static_cast<unsigned char>(value.size() << 1);
    std::memcpy(bytes + 1, value.data(), value.size());
    return;
  }

  const size_t capacity = value.size() + 1;
  char* storage = static_cast<char*>(std::malloc(capacity));
  if (storage == nullptr) {
    bytes[0] = 0;
    return;
  }
  std::memcpy(storage, value.data(), value.size());
  storage[value.size()] = '\0';

  auto* words = reinterpret_cast<uintptr_t*>(out);
  words[0] = (capacity + 1u) | 1u;
  words[1] = value.size();
  words[2] = reinterpret_cast<uintptr_t>(storage);
}

uintptr_t SeedStage6StringFieldValueScratch(uintptr_t source_string) {
  if (source_string != 0 &&
      source_string == g_stage6_string_field_value_scratch_source) {
    return reinterpret_cast<uintptr_t>(g_stage6_string_field_value_scratch);
  }

  const char* chars = nullptr;
  size_t length = 0;
  if (!ReadLibcxxStringView(source_string, &chars, &length)) {
    return 0;
  }

  std::string value(chars, length);
  std::memset(g_stage6_string_field_value_scratch, 0,
              sizeof(g_stage6_string_field_value_scratch));
  WriteLibcxxString(g_stage6_string_field_value_scratch, value);
  *reinterpret_cast<uint32_t*>(g_stage6_string_field_value_scratch + 0x18) =
      0x40000000u;
  *reinterpret_cast<uint32_t*>(g_stage6_string_field_value_scratch + 0x1c) =
      0x40000000u;
  g_stage6_string_field_value_scratch_source = source_string;
  return reinterpret_cast<uintptr_t>(g_stage6_string_field_value_scratch);
}

extern "C" void* mocktail_build_roblox_service_host_bridge(
    void* out, const char* service) {
  std::string host;
  if (service != nullptr && service[0] != '\0') {
    host = service;
    if (host.find('.') == std::string::npos) {
      host += ".roblox.com";
    }
  } else {
    host = "www.roblox.com";
  }
  WriteLibcxxString(out, host);
  return out;
}

bool PatchRobloxServiceHostBuilder(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_SERVICE_HOST_BUILDER")) {
    return false;
  }

  constexpr uintptr_t kServiceHostBuilderOffset = 0x2368b24;
  unsigned char patch[12] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t bridge =
      reinterpret_cast<uintptr_t>(&mocktail_build_roblox_service_host_bridge);
  std::memcpy(patch + 2, &bridge, sizeof(bridge));
  bool patched = PatchCode(
      reinterpret_cast<void*>(libroblox_base + kServiceHostBuilderOffset),
      patch, sizeof(patch));
  std::cout << "  [patch] Roblox service host builder bridge "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

constexpr uint64_t kRobloxAllocBridgeMagic = 0x4d54414c4c4f4331ULL;
constexpr size_t kRobloxAllocBridgeFrontPadding = 64;
constexpr size_t kRobloxAllocBridgeBackPadding = 4096;
constexpr size_t kRobloxEmutlsAllocBridgeBackPadding = 0x20000;

struct RobloxAllocBridgeHeader {
  uint64_t magic;
  size_t requested_size;
  size_t usable_size;
  void* raw;
};

struct EmutlsDefault {
  uintptr_t offset;
  size_t size;
  size_t align;
};

constexpr EmutlsDefault kKnownEmutlsDefaults[] = {
    {0x7022d40, 0x420, 0x20}, {0x7022d60, 0x1, 0x1},  {0x7068498, 0x8, 0x8},
    {0x70684b8, 0x238, 0x8},  {0x70684f8, 0x8, 0x8},  {0x7069a00, 0x20, 0x8},
    {0x706d1c8, 0x8, 0x8},    {0x706d1e8, 0x8, 0x8},  {0x706d208, 0x1, 0x1},
    {0x706d228, 0x10, 0x8},   {0x706d390, 0x20, 0x1},
};

struct EmutlsBridgeSlot {
  const void* key = nullptr;
  void* raw = nullptr;
  void* value = nullptr;
  size_t size = 0;
};

constexpr size_t kMaxEmutlsBridgeSlots = 256;

struct EmutlsBridgeThreadState {
  size_t slot_count = 0;
  EmutlsBridgeSlot slots[kMaxEmutlsBridgeSlots];
};

pthread_key_t g_emutls_bridge_pthread_key;
pthread_once_t g_emutls_bridge_pthread_key_once = PTHREAD_ONCE_INIT;

void InitEmutlsBridgePthreadKey() {
  pthread_key_create(&g_emutls_bridge_pthread_key, nullptr);
}

EmutlsBridgeThreadState* GetEmutlsBridgeThreadState() {
  pthread_once(&g_emutls_bridge_pthread_key_once, InitEmutlsBridgePthreadKey);
  auto* state = static_cast<EmutlsBridgeThreadState*>(
      pthread_getspecific(g_emutls_bridge_pthread_key));
  if (state != nullptr) {
    return state;
  }
  state = static_cast<EmutlsBridgeThreadState*>(
      std::calloc(1, sizeof(EmutlsBridgeThreadState)));
  if (state == nullptr) {
    return nullptr;
  }
  pthread_setspecific(g_emutls_bridge_pthread_key, state);
  return state;
}

bool LookupKnownEmutlsDefault(uintptr_t key, size_t* size, size_t* align) {
  uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
  if (base == 0 || key < base) {
    return false;
  }
  uintptr_t offset = key - base;
  for (const auto& entry : kKnownEmutlsDefaults) {
    if (entry.offset == offset) {
      *size = entry.size;
      *align = entry.align;
      return true;
    }
  }
  return false;
}

extern "C" void* mocktail_emutls_get_bridge(void* key_ptr) {
  if (key_ptr == nullptr) {
    return nullptr;
  }
  auto* state = GetEmutlsBridgeThreadState();
  if (state == nullptr) {
    return nullptr;
  }
  for (size_t i = 0; i < state->slot_count; ++i) {
    if (state->slots[i].key == key_ptr) {
      return state->slots[i].value;
    }
  }

  size_t size = 0;
  size_t align = 0;
  uintptr_t key = reinterpret_cast<uintptr_t>(key_ptr);
  const bool known = LookupKnownEmutlsDefault(key, &size, &align);
  const auto* words = reinterpret_cast<const uint64_t*>(key_ptr);
  if (!known && IsReadableMemoryRange(key, sizeof(uint64_t) * 2)) {
    size = static_cast<size_t>(words[0]);
    align = static_cast<size_t>(words[1]);
  }
  if (size == 0 || size > 0x200000) {
    size = 8;
  }
  if (align == 0 || align > 0x1000 || (align & (align - 1)) != 0) {
    align = 8;
  }
  if (align < 16) {
    align = 16;
  }

  size_t total = size + align + sizeof(void*) + 0x100;
  auto* raw = static_cast<unsigned char*>(std::calloc(1, total));
  if (raw == nullptr) {
    return nullptr;
  }
  uintptr_t value_address =
      (reinterpret_cast<uintptr_t>(raw + sizeof(void*) + align - 1) &
       ~(static_cast<uintptr_t>(align) - 1));
  auto* value = reinterpret_cast<unsigned char*>(value_address);
  reinterpret_cast<void**>(value)[-1] = raw;

  uintptr_t initializer = 0;
  if (!known && IsReadableMemoryRange(key + 0x18, sizeof(uint64_t))) {
    initializer = static_cast<uintptr_t>(words[3]);
  }
  if (initializer != 0 && IsReadableMemoryRange(initializer, size)) {
    std::memcpy(value, reinterpret_cast<const void*>(initializer), size);
  }

  if (state->slot_count < kMaxEmutlsBridgeSlots) {
    auto& slot = state->slots[state->slot_count++];
    slot.key = key_ptr;
    slot.raw = raw;
    slot.value = value;
    slot.size = size;
  }

  if (IsEnabled("MOCKTAIL_EMUTLS_BRIDGE_TRACE")) {
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    uintptr_t offset = (base != 0 && key >= base) ? key - base : 0;
    std::fprintf(stderr,
                 "  [emutls] key=%p off=0x%lx size=0x%zx align=0x%zx "
                 "value=%p known=%d\n",
                 key_ptr, static_cast<unsigned long>(offset), size, align,
                 value, known ? 1 : 0);
  }
  return value;
}

RobloxAllocBridgeHeader* RobloxAllocBridgeHeaderFromUser(void* ptr) {
  if (ptr == nullptr) {
    return nullptr;
  }
  auto* user = static_cast<unsigned char*>(ptr);
  auto* header = reinterpret_cast<RobloxAllocBridgeHeader*>(
      user - kRobloxAllocBridgeFrontPadding - sizeof(RobloxAllocBridgeHeader));
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(header),
                             sizeof(*header))) {
    return nullptr;
  }
  if (header->magic != kRobloxAllocBridgeMagic || header->raw == nullptr) {
    return nullptr;
  }
  return header;
}

extern "C" void* mocktail_roblox_small_alloc_bridge(size_t size) {
  uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  uintptr_t caller_rbx = 0;
  uintptr_t caller_r12 = 0;
  uintptr_t caller_r15 = 0;
#if defined(__x86_64__)
  asm volatile("mov %%rbx,%0" : "=r"(caller_rbx));
  asm volatile("mov %%r12,%0" : "=r"(caller_r12));
  asm volatile("mov %%r15,%0" : "=r"(caller_r15));
#endif
  uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
  uintptr_t offset = (base != 0 && caller >= base) ? caller - base : 0;
  if (size == 0) {
    size = 1;
  }
  if (offset == 0x2c18e79 || offset == 0x2c18ee8) {
    size_t total = size + kRobloxEmutlsAllocBridgeBackPadding;
    void* raw = std::calloc(1, total);
    if (IsEnabled("MOCKTAIL_ALLOC_TRACE")) {
      std::fprintf(stderr,
                   "  [alloc] caller=%p off=0x%lx emutls_raw size=0x%zx "
                   "total=0x%zx raw=%p rbx=%p r12=%p r15=%p\n",
                   reinterpret_cast<void*>(caller),
                   static_cast<unsigned long>(offset), size, total, raw,
                   reinterpret_cast<void*>(caller_rbx),
                   reinterpret_cast<void*>(caller_r12),
                   reinterpret_cast<void*>(caller_r15));
    }
    return raw;
  }
  size_t aligned = (size + 15u) & ~static_cast<size_t>(15u);
  size_t total = sizeof(RobloxAllocBridgeHeader) +
                 kRobloxAllocBridgeFrontPadding + aligned +
                 kRobloxAllocBridgeBackPadding;
  auto* raw = static_cast<unsigned char*>(std::calloc(1, total));
  if (raw == nullptr) {
    return nullptr;
  }
  auto* header = reinterpret_cast<RobloxAllocBridgeHeader*>(raw);
  header->magic = kRobloxAllocBridgeMagic;
  header->requested_size = size;
  header->usable_size = aligned;
  header->raw = raw;
  void* user =
      raw + sizeof(RobloxAllocBridgeHeader) + kRobloxAllocBridgeFrontPadding;
  if (IsEnabled("MOCKTAIL_ALLOC_TRACE")) {
    std::fprintf(stderr,
                 "  [alloc] caller=%p off=0x%lx size=0x%zx aligned=0x%zx "
                 "total=0x%zx raw=%p user=%p\n",
                 reinterpret_cast<void*>(caller),
                 static_cast<unsigned long>(offset), size, aligned, total, raw,
                 user);
  }
  return user;
}

extern "C" void* mocktail_roblox_aligned_alloc_bridge(size_t size,
                                                      size_t align) {
  if (align == 0) {
    align = 16;
  }
  if ((align & (align - 1)) != 0) {
    align = 16;
  }
  if (align <= 16) {
    return mocktail_roblox_small_alloc_bridge(size);
  }

  size_t aligned = (size + align - 1) & ~(align - 1);
  if (aligned == 0) {
    aligned = align;
  }
  size_t total = aligned + align + kRobloxAllocBridgeBackPadding;
  void* raw = std::calloc(1, total);
  if (raw == nullptr) {
    return nullptr;
  }
  uintptr_t user_address = (reinterpret_cast<uintptr_t>(raw) + align - 1) &
                           ~(static_cast<uintptr_t>(align) - 1);
  return reinterpret_cast<void*>(user_address);
}

extern "C" void* mocktail_roblox_allocator_object_alloc_bridge(void*,
                                                               size_t size,
                                                               size_t align) {
  return mocktail_roblox_aligned_alloc_bridge(size, align);
}

// Retained for the legacy fixed-offset allocator patch. Build-ID profiles keep
// their seed storage in compat/host_abi_experiment.
uintptr_t g_mocktail_roblox_allocator_object_vtable[4] = {};
uintptr_t g_mocktail_roblox_allocator_object[1] = {
    reinterpret_cast<uintptr_t>(g_mocktail_roblox_allocator_object_vtable)};

extern "C" void* mocktail_roblox_realloc_bridge(void* ptr, size_t size) {
  // Guard against overflowed new[] sizes that become bad_array_new_length.
  constexpr size_t kMaxHostRealloc = size_t{1} << 30;  // 1 GiB
  if (size > kMaxHostRealloc) {
    if (IsEnabled("MOCKTAIL_ALLOC_TRACE")) {
      std::fprintf(stderr, "  [realloc] reject oversized size=0x%zx\n", size);
    }
    return nullptr;
  }
  if (size == 0) {
    if (auto* header = RobloxAllocBridgeHeaderFromUser(ptr)) {
      header->magic = 0;
      std::free(header->raw);
    }
    return nullptr;
  }
  void* next = mocktail_roblox_small_alloc_bridge(size);
  if (next == nullptr || ptr == nullptr) {
    return next;
  }
  if (auto* header = RobloxAllocBridgeHeaderFromUser(ptr)) {
    std::memcpy(next, ptr, std::min(size, header->usable_size));
    header->magic = 0;
    std::free(header->raw);
  } else {
    // Unknown provenance: copy at most the new size, but never more than a
    // conservative page to avoid OOB reads from short native freelist blocks.
    const size_t copy_n = std::min(size, static_cast<size_t>(4096));
    if (IsReadableMemoryRange(reinterpret_cast<uintptr_t>(ptr), copy_n)) {
      std::memcpy(next, ptr, copy_n);
    }
  }
  return next;
}

// Free counterpart for host-owned allocations. Pointers without the Mocktail
// alloc header are ignored so native freelist walks do not touch uninit state
// after constructors are skipped on the host.
extern "C" void mocktail_roblox_free_bridge(void* ptr) {
  if (ptr == nullptr) {
    return;
  }
  if (auto* header = RobloxAllocBridgeHeaderFromUser(ptr)) {
    header->magic = 0;
    std::free(header->raw);
    return;
  }
  // Non-Mocktail pointers: do nothing. Safer than running Roblox freelist
  // code against an uninitialized arena table after skipped .init_array.
}

extern "C" size_t mocktail_roblox_usable_size_bridge(void* ptr) {
  if (auto* header = RobloxAllocBridgeHeaderFromUser(ptr)) {
    return header->usable_size;
  }
  return 0;
}

mocktail::compat::HostAbiExperimentResult g_host_abi_install_result;
bool g_host_abi_install_attempted = false;

bool HostAbiExperimentRequested() {
  return g_allow_host_abi_bridges.load(std::memory_order_acquire) &&
         !IsDisabled("MOCKTAIL_HOST_ABI_BRIDGES");
}

bool InstallActiveHostAbiExperiment(uintptr_t libroblox_base) {
  if (g_host_abi_install_attempted) {
    return static_cast<bool>(g_host_abi_install_result);
  }
  g_host_abi_install_attempted = true;
  if (!HostAbiExperimentRequested()) {
    std::cout << "  [compat] host ABI profile disabled by policy\n"
              << std::flush;
    return false;
  }

  const mocktail::compat::HostAbiProfile* profile =
      g_active_host_abi_profile.load(std::memory_order_acquire);
  if (libroblox_base == 0 || profile == nullptr) {
    std::cerr << "  [compat] host ABI install has no active profile/base\n"
              << std::flush;
    return false;
  }

  const mocktail::compat::HostAbiBridgeTargets targets{
      reinterpret_cast<void*>(&mocktail::compat::HostAllocate),
      reinterpret_cast<void*>(&mocktail::compat::HostReallocate),
      reinterpret_cast<void*>(&mocktail::compat::HostAlignedAllocate),
      reinterpret_cast<void*>(&mocktail::compat::HostFree),
      reinterpret_cast<void*>(&mocktail::compat::HostUsableSize),
      reinterpret_cast<void*>(&mocktail::compat::HostAllocatorObjectAllocate),
      reinterpret_cast<void*>(&NullVtableStub),
  };
  const char* allocator_bridge_override =
      std::getenv("MOCKTAIL_HOST_ALLOCATOR_BRIDGES");
  const mocktail::compat::HostAllocatorStrategy allocator_strategy =
      profile->ResolveAllocatorStrategy(
          allocator_bridge_override != nullptr,
          IsEnabled("MOCKTAIL_HOST_ALLOCATOR_BRIDGES"));
  const bool install_allocator_bridges =
      allocator_strategy ==
      mocktail::compat::HostAllocatorStrategy::kHostBridges;
  const mocktail::compat::HostAbiExperimentOptions options{
      install_allocator_bridges,
      install_allocator_bridges &&
          !IsDisabled("MOCKTAIL_HOST_ALLOCATOR_OBJECT"),
      install_allocator_bridges && !IsDisabled("MOCKTAIL_HOST_EMPTY_STRING"),
      install_allocator_bridges &&
          !IsDisabled("MOCKTAIL_HOST_ALLOC_ARENA_INIT"),
      install_allocator_bridges &&
          !IsDisabled("MOCKTAIL_HOST_JNI_SINGLETON_SEED"),
  };
  g_host_abi_install_result = mocktail::compat::InstallHostAbiExperiment(
      libroblox_base, *profile, targets, options);
  return static_cast<bool>(g_host_abi_install_result);
}

bool InitializeActiveHostAbiThread() {
  if (!HostAbiExperimentRequested()) {
    return true;
  }
  const mocktail::compat::HostAbiProfile* profile =
      g_active_host_abi_profile.load(std::memory_order_acquire);
  if (profile == nullptr || g_libroblox_base == 0) {
    return false;
  }
  return mocktail::compat::InitializeHostAbiThread(g_libroblox_base, *profile);
}

bool PatchRobloxSmallAllocator(uintptr_t libroblox_base) {
  if (libroblox_base == 0 || IsDisabled("MOCKTAIL_PATCH_ROBLOX_ALLOCATOR")) {
    return false;
  }

  constexpr uintptr_t kSmallAllocatorEntryOffset = 0x1f24322;
  unsigned char entry_patch[] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t bridge =
      reinterpret_cast<uintptr_t>(&mocktail_roblox_small_alloc_bridge);
  std::memcpy(entry_patch + 2, &bridge, sizeof(bridge));

  bool patched = PatchCode(
      reinterpret_cast<void*>(libroblox_base + kSmallAllocatorEntryOffset),
      entry_patch, sizeof(entry_patch));

  constexpr uintptr_t kAlignedAllocatorEntryOffset = 0x1ffc21c;
  unsigned char aligned_alloc_patch[] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t aligned_alloc_bridge =
      reinterpret_cast<uintptr_t>(&mocktail_roblox_aligned_alloc_bridge);
  std::memcpy(aligned_alloc_patch + 2, &aligned_alloc_bridge,
              sizeof(aligned_alloc_bridge));
  patched = PatchCode(reinterpret_cast<void*>(libroblox_base +
                                              kAlignedAllocatorEntryOffset),
                      aligned_alloc_patch, sizeof(aligned_alloc_patch)) &&
            patched;

  constexpr uintptr_t kAlignedAllocatorWrapperEntryOffset = 0x1f76aa5;
  unsigned char aligned_wrapper_patch[] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t aligned_wrapper_bridge =
      reinterpret_cast<uintptr_t>(&mocktail_roblox_aligned_alloc_bridge);
  std::memcpy(aligned_wrapper_patch + 2, &aligned_wrapper_bridge,
              sizeof(aligned_wrapper_bridge));
  const bool aligned_wrapper_patched =
      PatchCode(reinterpret_cast<void*>(libroblox_base +
                                        kAlignedAllocatorWrapperEntryOffset),
                aligned_wrapper_patch, sizeof(aligned_wrapper_patch));
  patched = aligned_wrapper_patched && patched;
  std::cout << "  [patch] Roblox aligned allocator wrapper bridge "
            << (aligned_wrapper_patched ? "installed" : "failed") << '\n'
            << std::flush;

  constexpr uintptr_t kReallocEntryOffset = 0x230959d;
  unsigned char realloc_patch[] = {
      0x48, 0xb8,                                // movabs rax, imm64
      0,    0,    0, 0, 0, 0, 0, 0, 0xff, 0xe0,  // jmp rax
  };
  uintptr_t realloc_bridge =
      reinterpret_cast<uintptr_t>(&mocktail_roblox_realloc_bridge);
  std::memcpy(realloc_patch + 2, &realloc_bridge, sizeof(realloc_bridge));
  patched =
      PatchCode(reinterpret_cast<void*>(libroblox_base + kReallocEntryOffset),
                realloc_patch, sizeof(realloc_patch)) &&
      patched;

  // Leave the older fast-path bypass in place for builds where the entry
  // trampoline signature is not reached before startup code calls the
  // allocator.
  constexpr uintptr_t kSmallAllocatorFastPathOffset = 0x1f24349;
  constexpr unsigned char kJumpToSlowPath[] = {
      0xeb, 0x32,  // jmp 0x1f2437d
      0x90, 0x90, 0x90, 0x90, 0x90,
  };
  patched = PatchCode(reinterpret_cast<void*>(libroblox_base +
                                              kSmallAllocatorFastPathOffset),
                      kJumpToSlowPath, sizeof(kJumpToSlowPath)) &&
            patched;

  constexpr uintptr_t kTlsAlignmentAbortBranchOffset = 0x2c18ed6;
  constexpr unsigned char kNopTlsAlignmentAbortBranch[] = {
      0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  };
  patched = PatchCode(reinterpret_cast<void*>(libroblox_base +
                                              kTlsAlignmentAbortBranchOffset),
                      kNopTlsAlignmentAbortBranch,
                      sizeof(kNopTlsAlignmentAbortBranch)) &&
            patched;
  std::cout << "  [patch] Roblox small allocator bridge "
            << (patched ? "installed" : "failed") << '\n'
            << std::flush;
  return patched;
}

bool PatchDataPointer(void** address, void* value) {
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0 || address == nullptr) {
    return false;
  }
  uintptr_t page = reinterpret_cast<uintptr_t>(address) &
                   ~(static_cast<uintptr_t>(page_size) - 1);
  if (mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(page_size),
               PROT_READ | PROT_WRITE) != 0) {
    return false;
  }
  *address = value;
  return true;
}

bool PatchRobloxAllocatorObject(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_ROBLOX_ALLOCATOR_OBJECT")) {
    return false;
  }

  constexpr uintptr_t kAllocatorObjectSlotOffset = 0x73edeb0;
  g_mocktail_roblox_allocator_object_vtable[0] =
      reinterpret_cast<uintptr_t>(&NullVtableStub);
  g_mocktail_roblox_allocator_object_vtable[1] =
      reinterpret_cast<uintptr_t>(&NullVtableStub);
  g_mocktail_roblox_allocator_object_vtable[2] = reinterpret_cast<uintptr_t>(
      &mocktail_roblox_allocator_object_alloc_bridge);
  g_mocktail_roblox_allocator_object_vtable[3] =
      reinterpret_cast<uintptr_t>(&NullVtableStub);

  auto** allocator_object_slot =
      reinterpret_cast<void**>(libroblox_base + kAllocatorObjectSlotOffset);
  void* original = nullptr;
  if (IsReadableMemoryRange(reinterpret_cast<uintptr_t>(allocator_object_slot),
                            sizeof(*allocator_object_slot))) {
    original = *allocator_object_slot;
  }
  bool patched = PatchDataPointer(
      allocator_object_slot,
      reinterpret_cast<void*>(g_mocktail_roblox_allocator_object));
  std::cout << "  [patch] Roblox allocator object bridge "
            << (patched ? "installed" : "failed") << " original=" << original
            << '\n'
            << std::flush;
  return patched;
}

bool PatchRobloxJniReferenceHighTagMask(uintptr_t libroblox_base);
bool PatchRobloxStackCheckBranches(uintptr_t libroblox_base);
bool PatchStage6StackCheckExceptionLandings(uintptr_t libroblox_base);
void** ExpandedSegmentTable();

bool EnvOffsetListContains(const char* name, uintptr_t offset) {
  const char* skip_list = std::getenv(name);
  if (skip_list == nullptr || *skip_list == '\0') {
    return false;
  }
  const char* cursor = skip_list;
  while (*cursor != '\0') {
    while (*cursor == ',' ||
           std::isspace(static_cast<unsigned char>(*cursor))) {
      ++cursor;
    }
    if (*cursor == '\0') {
      break;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(cursor, &end, 0);
    if (end == cursor) {
      break;
    }
    if (errno == 0 && static_cast<uintptr_t>(parsed) == offset) {
      return true;
    }
    cursor = end;
  }
  return false;
}

bool EnvIndexRangeListContains(const char* name, size_t index) {
  const char* range_list = std::getenv(name);
  if (range_list == nullptr || *range_list == '\0') {
    return false;
  }

  const char* cursor = range_list;
  while (*cursor != '\0') {
    while (*cursor == ',' ||
           std::isspace(static_cast<unsigned char>(*cursor))) {
      ++cursor;
    }
    if (*cursor == '\0') {
      break;
    }

    char* end = nullptr;
    unsigned long long start = std::strtoull(cursor, &end, 0);
    if (end == cursor) {
      break;
    }

    unsigned long long stop = start;
    cursor = end;
    if (*cursor == '-') {
      ++cursor;
      char* range_end = nullptr;
      stop = std::strtoull(cursor, &range_end, 0);
      if (range_end == cursor) {
        break;
      }
      cursor = range_end;
    }

    if (start <= index && index <= stop) {
      return true;
    }

    while (*cursor != '\0' && *cursor != ',') {
      ++cursor;
    }
  }

  return false;
}

bool ConstructorPatchOffsetSkipped(uintptr_t offset) {
  return EnvOffsetListContains("MOCKTAIL_SKIP_CONSTRUCTOR_PATCH_OFFSETS",
                               offset);
}

bool LibRobloxConstructorOffsetSkipped(uintptr_t offset) {
  return EnvOffsetListContains("MOCKTAIL_SKIP_LIBROBLOX_CTOR_OFFSETS", offset);
}

bool LibRobloxConstructorIndexSkipped(size_t index) {
  return EnvIndexRangeListContains("MOCKTAIL_SKIP_LIBROBLOX_CTOR_INDEX_RANGES",
                                   index);
}

bool LibRobloxConstructorIndexAllowed(size_t index) {
  return EnvIndexRangeListContains("MOCKTAIL_ALLOW_LIBROBLOX_CTOR_INDEX_RANGES",
                                   index);
}

bool PatchRobloxConstructorCrashpadLogging(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_PATCH_CONSTRUCTOR_CRASHPAD_LOGGING")) {
    return false;
  }
  constexpr uintptr_t kCrashpadLoggingOffsets[] = {
      0x1f26b76, 0x1f28d7d, 0x1f332f4, 0x1f336e2, 0x1f535f0, 0x1f58db0,
      0x1faa5fe, 0x1faaec8, 0x1fbb2b9, 0x2300b45, 0x232c906, 0x2c57993,
      0x2c5799c, 0x2bfc300, 0x2bfc7c0, 0x2bfc7c6, 0x2bfcb80, 0x2c74090,
      0x2c74096, 0x2c1e25d, 0x2c17a70, 0x2c17a9b, 0x2c17860, 0x2c178d0,
      0x2c18d80, 0x2c19350, 0x277c510, 0x277c550, 0x2c7caa4, 0x2c7cbfc,
      0x306a42e,
  };
  constexpr unsigned char kReturn[] = {0xc3};
  unsigned char return_pad[256];
  std::memset(return_pad, 0xc3, sizeof(return_pad));
  constexpr unsigned char kReturnArgument[] = {
      0x48,
      0x89,
      0xf8,  // mov rax, rdi
      0xc3,  // ret
  };
  constexpr unsigned char kReturnFalse[] = {
      0x31,
      0xc0,  // xor eax, eax
      0xc3,  // ret
  };
  constexpr unsigned char kMoveXmm1FromXmm0[] = {
      0xf3, 0x0f, 0x10, 0xc8,  // movss xmm1, xmm0
      0x90,                    // nop
  };
  constexpr unsigned char kPopFrameReturn[] = {
      0x5d,  // pop rbp
      0xc3,  // ret
  };
  constexpr unsigned char kReturnFromSavedRbxAndScratch[] = {
      0x48, 0x83, 0xc4, 0x08,  // add rsp, 8
      0x5b,                    // pop rbx
      0x5d,                    // pop rbp
      0xc3,                    // ret
  };
  constexpr unsigned char kReturnFromSavedR15R14RbxAndScratch[] = {
      0x48, 0x83, 0xc4, 0x08,  // add rsp, 8
      0x5b,                    // pop rbx
      0x41, 0x5e,              // pop r14
      0x41, 0x5f,              // pop r15
      0x5d,                    // pop rbp
      0xc3,                    // ret
  };
  bool patched = true;
  for (uintptr_t offset : kCrashpadLoggingOffsets) {
    if (ConstructorPatchOffsetSkipped(offset)) {
      std::cout << "  [patch] constructor offset 0x" << std::hex << offset
                << std::dec << " left unpatched by env\n"
                << std::flush;
      continue;
    }
    if (offset == 0x2c5799c || offset == 0x2c74096) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           return_pad, sizeof(return_pad));
    } else if (offset == 0x2c17a70) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kReturnFromSavedR15R14RbxAndScratch,
                           sizeof(kReturnFromSavedR15R14RbxAndScratch));
    } else if (offset == 0x2c17860 || offset == 0x2bfc7c0 ||
               offset == 0x277c510 || offset == 0x277c550) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kReturnFalse, sizeof(kReturnFalse));
    } else if (offset == 0x2bfc7c6) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kPopFrameReturn, sizeof(kPopFrameReturn));
    } else if (offset == 0x2300b45) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kMoveXmm1FromXmm0, sizeof(kMoveXmm1FromXmm0));
    } else if (offset == 0x2c17a9b) {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kReturnFromSavedRbxAndScratch,
                           sizeof(kReturnFromSavedRbxAndScratch));
    } else if (offset == 0x2c178d0 || offset == 0x2c18d80) {
      patched = SaveOriginalConstructorEmutlsHelper(libroblox_base, offset) &&
                patched;
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kReturnArgument, sizeof(kReturnArgument));
    } else {
      patched &= PatchCode(reinterpret_cast<void*>(libroblox_base + offset),
                           kReturn, sizeof(kReturn));
    }
  }
  std::cout << "  [patch] constructor crashpad logging "
            << (patched ? "disabled" : "failed") << '\n'
            << std::flush;
  return patched;
}

static size_t g_current_ctor_index = 0;
static std::vector<uintptr_t> g_original_ctors;
uintptr_t g_libroblox_base_static = 0;
static size_t g_libroblox_ctor_start_index = 0;
static size_t g_libroblox_ctor_end_index = 0;
static size_t g_libroblox_ctor_executed_count = 0;
static size_t g_libroblox_ctor_skipped_range_count = 0;
static size_t g_libroblox_ctor_skipped_default_count = 0;
static size_t g_libroblox_ctor_skipped_index_count = 0;
static size_t g_libroblox_ctor_skipped_env_count = 0;
static size_t g_libroblox_ctor_recovered_count = 0;

bool LibRobloxConstructorAutoRecoveryEnabled() {
  return IsEnabled("MOCKTAIL_RUN_LIBROBLOX_CTORS") &&
         !IsDisabled("MOCKTAIL_RECOVER_LIBROBLOX_CTOR_CRASHES");
}

bool LibRobloxConstructorDefaultQuarantineEnabled() {
  // The Build-ID profile already supplies the final allowlisted range.
  // Applying the legacy "only index 0" quarantine on top would contradict it.
  if (g_allow_host_constructor_replay.load(std::memory_order_acquire)) {
    return false;
  }
  if (!IsEnabled("MOCKTAIL_RUN_LIBROBLOX_CTORS")) {
    return false;
  }
  if (IsDisabled("MOCKTAIL_QUARANTINE_LIBROBLOX_UNSAFE_CTORS")) {
    return false;
  }
  const char* policy = std::getenv("MOCKTAIL_LIBROBLOX_CTOR_POLICY");
  if (policy != nullptr &&
      (std::strcmp(policy, "all") == 0 || std::strcmp(policy, "unsafe") == 0)) {
    return false;
  }
  return true;
}

bool LibRobloxConstructorDefaultQuarantineSkipped(size_t index) {
  if (!LibRobloxConstructorDefaultQuarantineEnabled()) {
    return false;
  }
  if (index == 0 || LibRobloxConstructorIndexAllowed(index)) {
    return false;
  }
  return true;
}

size_t GetCtorIndexEnv(const char* name, size_t default_value,
                       size_t max_value) {
  int value = GetEnvInt(name, -1);
  if (value < 0) {
    return default_value;
  }
  return std::min(static_cast<size_t>(value), max_value);
}

void MaybePrintLibRobloxConstructorSummary(size_t idx) {
  if (idx + 1 != g_original_ctors.size()) {
    return;
  }
  std::cout << "  [ctor] Summary: executed=" << g_libroblox_ctor_executed_count
            << " recovered=" << g_libroblox_ctor_recovered_count
            << " skipped_by_range=" << g_libroblox_ctor_skipped_range_count
            << " skipped_by_default=" << g_libroblox_ctor_skipped_default_count
            << " skipped_by_index=" << g_libroblox_ctor_skipped_index_count
            << " skipped_by_env=" << g_libroblox_ctor_skipped_env_count << '\n'
            << std::flush;
}

extern "C" void MocktailConstructorWrapper() {
  if (g_current_ctor_index >= g_original_ctors.size()) {
    std::cerr << "  [ctor] Warning: constructor index " << g_current_ctor_index
              << " out of bounds!\n"
              << std::flush;
    return;
  }
  size_t idx = g_current_ctor_index++;
  uintptr_t orig = g_original_ctors[idx];
  uintptr_t offset = orig - g_libroblox_base_static;
  const bool trace_constructor = LibRobloxConstructorTraceEnabled();
  if (trace_constructor) {
    std::cout << "  [ctor] [" << idx << "/" << g_original_ctors.size()
              << "] offset 0x" << std::hex << offset << std::dec << '\n'
              << std::flush;
  }
  if (idx < g_libroblox_ctor_start_index || idx >= g_libroblox_ctor_end_index) {
    ++g_libroblox_ctor_skipped_range_count;
    if (trace_constructor) {
      std::cout << "  [ctor] [" << idx << "] Skipped by ctor index range.\n"
                << std::flush;
    }
    MaybePrintLibRobloxConstructorSummary(idx);
    return;
  }
  const mocktail::compat::HostAbiProfile* active_host_profile =
      g_active_host_abi_profile.load(std::memory_order_acquire);
  const bool use_native_mimalloc =
      g_host_abi_install_attempted &&
      g_host_abi_install_result.uses_native_mimalloc;
  if (g_allow_host_constructor_replay.load(std::memory_order_acquire) &&
      active_host_profile != nullptr &&
      !(use_native_mimalloc
            ? active_host_profile->AllowsNativeMimallocConstructor(idx)
            : active_host_profile->AllowsConstructor(idx))) {
    ++g_libroblox_ctor_skipped_range_count;
    if (trace_constructor) {
      std::cout << "  [ctor] [" << idx << "] Skipped by typed "
                << (use_native_mimalloc ? "native Mimalloc" : "host bridge")
                << " run ranges.\n"
                << std::flush;
    }
    MaybePrintLibRobloxConstructorSummary(idx);
    return;
  }
  if (LibRobloxConstructorDefaultQuarantineSkipped(idx)) {
    ++g_libroblox_ctor_skipped_default_count;
    if (trace_constructor) {
      std::cout << "  [ctor] [" << idx
                << "] Skipped by default unsafe ctor quarantine.\n"
                << std::flush;
    }
    MaybePrintLibRobloxConstructorSummary(idx);
    return;
  }
  if (LibRobloxConstructorIndexSkipped(idx)) {
    ++g_libroblox_ctor_skipped_index_count;
    if (trace_constructor) {
      std::cout << "  [ctor] [" << idx << "] Skipped by ctor index env.\n"
                << std::flush;
    }
    MaybePrintLibRobloxConstructorSummary(idx);
    return;
  }
  if (LibRobloxConstructorOffsetSkipped(offset)) {
    ++g_libroblox_ctor_skipped_env_count;
    if (trace_constructor) {
      std::cout << "  [ctor] [" << idx << "] Skipped by env.\n" << std::flush;
    }
    MaybePrintLibRobloxConstructorSummary(idx);
    return;
  }
  if (trace_constructor) {
    std::cout << "  [ctor] [" << idx << "] Executing.\n" << std::flush;
  }
  void (*fn)() = reinterpret_cast<void (*)()>(orig);
  if (LibRobloxConstructorAutoRecoveryEnabled()) {
    g_libroblox_ctor_recovered_signo = 0;
    g_libroblox_ctor_recovered_rip = 0;
    g_libroblox_ctor_recovered_si_addr = 0;
    if (sigsetjmp(g_libroblox_ctor_jmp_buf, 1) != 0) {
      DisarmLibRobloxConstructorAlarm();
      ++g_libroblox_ctor_recovered_count;
      uintptr_t rip = static_cast<uintptr_t>(g_libroblox_ctor_recovered_rip);
      uintptr_t rip_offset =
          (g_libroblox_base_static != 0 && rip >= g_libroblox_base_static &&
           rip < g_libroblox_base_static + 0x08000000)
              ? rip - g_libroblox_base_static
              : 0;
      std::cout << "  [ctor] [" << idx << "] Auto-recovered signal "
                << static_cast<int>(g_libroblox_ctor_recovered_signo)
                << " offset 0x" << std::hex << offset << " rip_off=0x"
                << rip_offset << " si_addr=0x"
                << static_cast<uintptr_t>(g_libroblox_ctor_recovered_si_addr)
                << std::dec << "\n"
                << std::flush;
      MaybePrintLibRobloxConstructorSummary(idx);
      return;
    }
    g_libroblox_ctor_recovery_in_progress = 1;
    ArmLibRobloxConstructorAlarm();
    fn();
    g_libroblox_ctor_recovery_in_progress = 0;
    DisarmLibRobloxConstructorAlarm();
  } else {
    fn();
  }
  if (use_native_mimalloc && active_host_profile != nullptr) {
    const mocktail::compat::NativeMimallocBootstrapStatus bootstrap_status =
        mocktail::compat::CompleteNativeMimallocConstructor(
            g_libroblox_base_static, *active_host_profile, idx);
    if (bootstrap_status ==
        mocktail::compat::NativeMimallocBootstrapStatus::kInitialized) {
      std::cout << "  [ctor] Native mimalloc thread state initialized after ["
                << idx << "]\n"
                << std::flush;
    } else if (bootstrap_status ==
               mocktail::compat::NativeMimallocBootstrapStatus::kFailed) {
      std::cerr << "  [ctor] Native mimalloc thread state initialization "
                   "failed after ["
                << idx << "]\n"
                << std::flush;
    }
  }
  ++g_libroblox_ctor_executed_count;
  if (trace_constructor) {
    std::cout << "  [ctor] [" << idx << "] Done.\n" << std::flush;
  }
  MaybePrintLibRobloxConstructorSummary(idx);
}

extern "C" void mocktail_before_soinfo_constructors(const char* realpath,
                                                    uintptr_t base) {
  if (realpath == nullptr || std::strstr(realpath, "libroblox.so") == nullptr ||
      base == 0) {
    return;
  }

  g_libroblox_base = base;
  g_mocktail_abort_libroblox_base = base;
  g_libroblox_base_static = base;

  const mocktail::compat::HostAbiProfile* host_abi =
      g_active_host_abi_profile.load(std::memory_order_acquire);

  // Host alloc bridges must be in place before any constructor executes.
  if (HostAbiExperimentRequested() && !InstallActiveHostAbiExperiment(base)) {
    std::cerr << "  [compat] host ABI install failed before constructors\n"
              << std::flush;
    return;
  }

  const bool force_run_ctors =
      (std::getenv("MOCKTAIL_SKIP_LIBROBLOX_CTORS") != nullptr &&
       std::strcmp(std::getenv("MOCKTAIL_SKIP_LIBROBLOX_CTORS"), "0") == 0) ||
      IsEnabled("MOCKTAIL_RUN_LIBROBLOX_CTORS");
  const bool want_light_wrap =
      IsEnabled("MOCKTAIL_WRAP_LIBROBLOX_CTORS") || force_run_ctors;
  const bool use_native_mimalloc =
      g_host_abi_install_attempted &&
      g_host_abi_install_result.uses_native_mimalloc;
  mocktail::compat::NativeThreadInitializer thread_initializer = nullptr;
  if (use_native_mimalloc && host_abi != nullptr &&
      host_abi->data_seeds.allocator_thread_initializer != 0) {
    thread_initializer =
        reinterpret_cast<mocktail::compat::NativeThreadInitializer>(
            base + host_abi->data_seeds.allocator_thread_initializer);
  }
  mocktail::compat::ConfigureBionicPthreadThreadInitializer(thread_initializer);
  libc_shim::GuestAllocator guest_allocator = nullptr;
  if (use_native_mimalloc && host_abi != nullptr &&
      host_abi->native_allocator.IsValid()) {
    guest_allocator = reinterpret_cast<libc_shim::GuestAllocator>(
        base + host_abi->native_allocator.allocate);
  }
  libc_shim::ConfigureGuestAllocator(guest_allocator);
  const bool has_selected_constructor_ranges =
      host_abi != nullptr &&
      (use_native_mimalloc ? host_abi->HasValidNativeMimallocConstructorRanges()
                           : host_abi->HasValidConstructorRanges());
  const bool have_init_array =
      g_allow_host_constructor_replay.load(std::memory_order_acquire) &&
      HostAbiExperimentRequested() && host_abi != nullptr &&
      host_abi->init_array_offset != 0 && has_selected_constructor_ranges;
  const bool allow_full_legacy = LegacyBinaryPatchesAllowed();

  if (!allow_full_legacy && !(want_light_wrap && have_init_array)) {
    std::cout << "  [compat] leaving libroblox constructors untouched for "
                 "this Build-ID profile\n"
              << std::flush;
    return;
  }

  g_current_ctor_index = 0;
  g_libroblox_ctor_executed_count = 0;
  g_libroblox_ctor_skipped_range_count = 0;
  g_libroblox_ctor_skipped_default_count = 0;
  g_libroblox_ctor_skipped_index_count = 0;
  g_libroblox_ctor_skipped_env_count = 0;
  g_libroblox_ctor_recovered_count = 0;
  if (allow_full_legacy && LibRobloxConstructorAutoRecoveryEnabled()) {
    InstallLibRobloxConstructorAlarm();
  }

  size_t kCtorCount = allow_full_legacy ? (0x69e0 / 8) : 0;
  uintptr_t init_array_offset = 0x7015af0;
  if (have_init_array) {
    init_array_offset = host_abi->init_array_offset;
    kCtorCount = host_abi->init_array_count;
  }
  const size_t profile_ctor_start =
      have_init_array ? (use_native_mimalloc
                             ? host_abi->NativeMimallocConstructorRangeBegin()
                             : host_abi->ConstructorRangeBegin())
                      : 0;
  const size_t profile_ctor_end =
      have_init_array
          ? (use_native_mimalloc
                 ? host_abi->NativeMimallocConstructorRangeEndExclusive()
                 : host_abi->ConstructorRangeEndExclusive())
          : kCtorCount;
  g_libroblox_ctor_start_index = std::max(
      profile_ctor_start, GetCtorIndexEnv("MOCKTAIL_LIBROBLOX_CTOR_START_INDEX",
                                          profile_ctor_start, kCtorCount));
  g_libroblox_ctor_end_index = std::min(
      profile_ctor_end, GetCtorIndexEnv("MOCKTAIL_LIBROBLOX_CTOR_END_INDEX",
                                        profile_ctor_end, kCtorCount));
  int max_ctors = GetEnvInt("MOCKTAIL_MAX_LIBROBLOX_CTORS", -1);
  if (max_ctors >= 0) {
    g_libroblox_ctor_end_index =
        std::min(g_libroblox_ctor_end_index,
                 g_libroblox_ctor_start_index + static_cast<size_t>(max_ctors));
  }
  if (g_libroblox_ctor_end_index < g_libroblox_ctor_start_index) {
    g_libroblox_ctor_end_index = g_libroblox_ctor_start_index;
  }
  uintptr_t* init_array =
      reinterpret_cast<uintptr_t*>(base + init_array_offset);

  long ctor_page_size = sysconf(_SC_PAGESIZE);
  if (ctor_page_size > 0) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(init_array);
    uintptr_t page = addr & ~(static_cast<uintptr_t>(ctor_page_size) - 1);
    const size_t span =
        (kCtorCount * sizeof(uintptr_t)) + static_cast<size_t>(ctor_page_size);
    mprotect(reinterpret_cast<void*>(page), span, PROT_READ | PROT_WRITE);
  }

  g_original_ctors.clear();
  g_original_ctors.reserve(kCtorCount);
  for (size_t i = 0; i < kCtorCount; ++i) {
    g_original_ctors.push_back(init_array[i]);
    if (i == 0 && IsEnabled("MOCKTAIL_PATCH_FIRST_CONSTRUCTOR")) {
      static void (*noop_fn)() = []() {};
      g_original_ctors[i] = reinterpret_cast<uintptr_t>(noop_fn);
    }
    init_array[i] = reinterpret_cast<uintptr_t>(MocktailConstructorWrapper);
  }
  std::cout << "  [compat] wrapping .init_array @+0x" << std::hex
            << init_array_offset << std::dec << " count=" << kCtorCount << '\n'
            << std::flush;
  std::cout << "  [compat] Wrapped " << kCtorCount
            << " constructors for typed replay"
            << (LibRobloxConstructorTraceEnabled() ? " with trace" : "") << '\n'
            << std::flush;
  std::cout << "  [ctor] Active index range [" << g_libroblox_ctor_start_index
            << ", " << g_libroblox_ctor_end_index << ")\n"
            << std::flush;
  if (use_native_mimalloc) {
    std::cout << "  [ctor] Native mimalloc integration probe selected; "
                 "host allocator bridges are disabled\n"
              << std::flush;
  }
  if (LibRobloxConstructorDefaultQuarantineEnabled()) {
    std::cout
        << "  [ctor] Default unsafe ctor quarantine enabled: only index 0 "
           "runs unless MOCKTAIL_ALLOW_LIBROBLOX_CTOR_INDEX_RANGES allows "
           "more\n"
        << std::flush;
  } else {
    std::cout << "  [ctor] Default unsafe ctor quarantine disabled\n"
              << std::flush;
  }

  // Legacy fixed-offset patches only when the Build-ID profile allows them.
  // Host ABI bridges already installed above for known Build IDs.
  if (allow_full_legacy) {
    PatchRobloxSmallAllocator(base);
    PatchRobloxJniReferenceHighTagMask(base);
    PatchRobloxConstructorCrashpadLogging(base);
    RestoreKnownRobloxEmutlsKeys(base);
    PatchRobloxEmutlsGetBridge(base);
    PatchRobloxStackCheckBranches(base);
    PatchStage6StackCheckExceptionLandings(base);

    auto** segment_table_ptr = reinterpret_cast<void**>(base + 0x75a2a40);
    void** expanded_segment_table = ExpandedSegmentTable();
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0 && expanded_segment_table != nullptr) {
      uintptr_t addr = reinterpret_cast<uintptr_t>(segment_table_ptr);
      uintptr_t page = addr & ~(static_cast<uintptr_t>(page_size) - 1);
      if (mprotect(reinterpret_cast<void*>(page),
                   static_cast<size_t>(page_size),
                   PROT_READ | PROT_WRITE) == 0) {
        *segment_table_ptr = expanded_segment_table;
        mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(page_size),
                 PROT_READ | PROT_WRITE | PROT_EXEC);
        std::cout << "  [patch] early Roblox segment table installed\n"
                  << std::flush;
      } else {
        std::cerr << "  [patch] early segment table mprotect failed: "
                  << std::strerror(errno) << '\n'
                  << std::flush;
      }
    }
  }
}

extern "C" bool mocktail_should_skip_soinfo_constructors(const char* realpath) {
  if (realpath == nullptr || std::strstr(realpath, "libroblox.so") == nullptr) {
    return false;
  }

  const bool typed_replay_allowed =
      g_allow_host_constructor_replay.load(std::memory_order_acquire) &&
      HostAbiExperimentRequested();
  const bool legacy_replay_allowed = LegacyBinaryPatchesAllowed();
  if (!typed_replay_allowed && !legacy_replay_allowed) {
    std::cout << "  [compat] skipping libroblox constructors: no exact "
                 "Build-ID replay policy\n"
              << std::flush;
    return true;
  }

  // Explicit host ABI policy, independent of fixed-offset binary patches.
  // Native libroblox .init_array currently aborts in emutls growth on Linux
  // hosts (caller off≈0x28bae15 on 2.725.1142). Skip by default for
  // non-patched profiles so name-based JNI startup remains reachable.
  //
  // Controls:
  //   MOCKTAIL_SKIP_LIBROBLOX_CTORS=1  force skip
  //   MOCKTAIL_SKIP_LIBROBLOX_CTORS=0  force run
  //   MOCKTAIL_RUN_LIBROBLOX_CTORS=1   force run (legacy name)
  const char* skip_constructors = std::getenv("MOCKTAIL_SKIP_LIBROBLOX_CTORS");
  if (skip_constructors != nullptr) {
    if (std::strcmp(skip_constructors, "0") == 0) {
      std::cout << "  [compat] running libroblox static constructors "
                   "(MOCKTAIL_SKIP_LIBROBLOX_CTORS=0)\n"
                << std::flush;
      return false;
    }
    std::cout << "  [compat] skipping libroblox static constructors "
                 "(MOCKTAIL_SKIP_LIBROBLOX_CTORS)\n"
              << std::flush;
    return true;
  }

  const char* run_constructors = std::getenv("MOCKTAIL_RUN_LIBROBLOX_CTORS");
  if (run_constructors != nullptr && std::strcmp(run_constructors, "0") != 0) {
    std::cout << "  [compat] running libroblox static constructors "
                 "(MOCKTAIL_RUN_LIBROBLOX_CTORS)\n"
              << std::flush;
    return false;
  }

  if (typed_replay_allowed && !legacy_replay_allowed) {
    std::cout
        << "  [compat] skipping libroblox static constructors for host load "
           "(set MOCKTAIL_SKIP_LIBROBLOX_CTORS=0 to force native .init_array)\n"
        << std::flush;
    return true;
  }

  std::cout << "  [patch] skipping libroblox static constructors"
            << " (set MOCKTAIL_RUN_LIBROBLOX_CTORS=1 to enable)\n"
            << std::flush;
  return true;
}

}  // namespace mocktail::legacy::internal
