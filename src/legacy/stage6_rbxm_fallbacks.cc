#include "legacy/stage6_rbxm_fallbacks.h"

#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
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

namespace mocktail::legacy::internal {

alignas(16) unsigned char g_stage6_start_lua_registry_scratch[0x180];
alignas(16) unsigned char g_stage6_rbxm_file_manager_cache_registry_entry[0x20];
alignas(
    16) unsigned char g_stage6_rbxm_file_manager_feature_registry_node[0x40];
alignas(16) uintptr_t g_stage6_rbxm_file_manager_feature_registry_buckets[2];
alignas(16) unsigned char g_headless_singleton_backing[0x338];
alignas(8) uintptr_t g_stage6_system_dialog_singleton_guard = 0;
alignas(8) uintptr_t g_stage6_system_dialog_dependency_singleton_guard = 0;

bool InstallStage6StartLuaRegistryFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_START_LUA_REGISTRY_FALLBACK")) {
    return false;
  }

  auto** slot = reinterpret_cast<unsigned char**>(
      libroblox_base + kStage6StartLuaRegistryGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(slot),
                             sizeof(*slot))) {
    std::cerr << "  [patch] Stage6 StartLua registry global is unreadable\n"
              << std::flush;
    return false;
  }
  if (*slot != nullptr) {
    if (EngineTraceEnabled()) {
      std::cout << "  [patch] Stage6 StartLua registry global already set "
                << "ptr=" << static_cast<void*>(*slot) << '\n'
                << std::flush;
    }
    return false;
  }

  std::memset(g_stage6_start_lua_registry_scratch, 0,
              sizeof(g_stage6_start_lua_registry_scratch));
  constexpr uint32_t kOneFloatBits = 0x3f800000;
  std::memcpy(g_stage6_start_lua_registry_scratch + 0x50, &kOneFloatBits,
              sizeof(kOneFloatBits));

  if (!EnsureWritablePage(slot)) {
    std::cerr << "  [patch] Stage6 StartLua registry global mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }
  *slot = g_stage6_start_lua_registry_scratch;
  std::cout << "  [patch] installed Stage6 StartLua registry fallback at 0x"
            << std::hex << kStage6StartLuaRegistryGlobalOffset << std::dec
            << " ptr="
            << static_cast<void*>(g_stage6_start_lua_registry_scratch) << '\n'
            << std::flush;
  return true;
}

bool InstallStage6RbxmFileManagerCacheRegistryFallback(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_RBXM_FILE_MANAGER_CACHE_REGISTRY")) {
    return false;
  }

  auto* registry = reinterpret_cast<void*>(
      libroblox_base + kStage6RbxmFileManagerCacheRegistryGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(registry), 0x38)) {
    std::cerr << "  [patch] Stage6 RbxmFileManager cache registry global "
              << "is unreadable\n"
              << std::flush;
    return false;
  }

  const uintptr_t registry_address = reinterpret_cast<uintptr_t>(registry);
  if (ReadPointerIfReadable(registry_address + 0x00) != 0 ||
      ReadPointerIfReadable(registry_address + 0x08) != 0 ||
      ReadPointerIfReadable(registry_address + 0x10) != 0 ||
      ReadPointerIfReadable(registry_address + 0x18) != 0) {
    if (EngineTraceEnabled()) {
      char cache_registry_preview[420];
      ReadRbxmFileManagerCacheRegistryPreview(libroblox_base,
                                              cache_registry_preview,
                                              sizeof(cache_registry_preview));
      std::cout << "  [patch] Stage6 RbxmFileManager cache registry "
                << "already initialized " << cache_registry_preview << '\n'
                << std::flush;
    }
    return false;
  }

  auto* init_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6RbxmFileManagerCacheRegistryInitOffset);
  constexpr unsigned char kExpectedInitPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41,
      0x56, 0x53, 0x50, 0x0f, 0x57, 0xc0,
  };
  if (std::memcmp(init_address, kExpectedInitPrologue,
                  sizeof(kExpectedInitPrologue)) != 0) {
    std::cerr << "  [patch] Stage6 RbxmFileManager cache registry init "
              << "signature mismatch at 0x" << std::hex
              << kStage6RbxmFileManagerCacheRegistryInitOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  if (!EnsureWritablePage(registry)) {
    std::cerr << "  [patch] Stage6 RbxmFileManager cache registry mprotect "
              << "failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  std::memset(g_stage6_rbxm_file_manager_cache_registry_entry, 0,
              sizeof(g_stage6_rbxm_file_manager_cache_registry_entry));
  WriteLibcxxString(g_stage6_rbxm_file_manager_cache_registry_entry,
                    kStage6UniversalAppRbxmUri);

  using CacheRegistryInitFn = void (*)(void*, const void*, uintptr_t);
  auto* init = reinterpret_cast<CacheRegistryInitFn>(init_address);
  init(registry, g_stage6_rbxm_file_manager_cache_registry_entry, 1);

  char cache_registry_preview[420];
  ReadRbxmFileManagerCacheRegistryPreview(
      libroblox_base, cache_registry_preview, sizeof(cache_registry_preview));
  const bool initialized =
      ReadPointerIfReadable(registry_address + 0x08) != 0 ||
      ReadPointerIfReadable(registry_address + 0x18) != 0;
  std::cout
      << "  [patch] installed Stage6 RbxmFileManager cache registry fallback "
      << "uri=\"" << kStage6UniversalAppRbxmUri << "\" "
      << cache_registry_preview << '\n'
      << std::flush;
  return initialized;
}

bool InstallStage6RbxmFileManagerFeatureRegistryFallback(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled(
          "MOCKTAIL_INSTALL_STAGE6_RBXM_FILE_MANAGER_FEATURE_REGISTRY")) {
    return false;
  }

  auto* registry = reinterpret_cast<void*>(
      libroblox_base + kStage6RbxmFileManagerFeatureRegistryGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(registry), 0x28)) {
    std::cerr << "  [patch] Stage6 RbxmFileManager feature registry global "
              << "is unreadable\n"
              << std::flush;
    return false;
  }

  const uintptr_t registry_address = reinterpret_cast<uintptr_t>(registry);
  if (ReadPointerIfReadable(registry_address + 0x00) != 0 ||
      ReadPointerIfReadable(registry_address + 0x08) != 0 ||
      ReadPointerIfReadable(registry_address + 0x10) != 0 ||
      ReadPointerIfReadable(registry_address + 0x18) != 0) {
    if (EngineTraceEnabled()) {
      char feature_registry_preview[520];
      ReadRbxmFileManagerFeatureRegistryPreview(
          libroblox_base, feature_registry_preview,
          sizeof(feature_registry_preview));
      std::cout << "  [patch] Stage6 RbxmFileManager feature registry "
                << "already initialized " << feature_registry_preview << '\n'
                << std::flush;
    }
    return false;
  }

  auto* hash_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6RbxmFileManagerFeatureRegistryHashOffset);
  constexpr unsigned char kExpectedHashPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec, 0x18,
  };
  if (std::memcmp(hash_address, kExpectedHashPrologue,
                  sizeof(kExpectedHashPrologue)) != 0) {
    std::cerr << "  [patch] Stage6 RbxmFileManager feature registry hash "
              << "signature mismatch at 0x" << std::hex
              << kStage6RbxmFileManagerFeatureRegistryHashOffset << std::dec
              << '\n'
              << std::flush;
    return false;
  }

  auto* mutex = reinterpret_cast<void*>(
      libroblox_base + kStage6RbxmFileManagerFeatureRegistryMutexGlobalOffset);
  if (!EnsureWritablePage(registry) || !EnsureWritablePage(mutex)) {
    std::cerr << "  [patch] Stage6 RbxmFileManager feature registry "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  std::memset(g_stage6_rbxm_file_manager_feature_registry_node, 0,
              sizeof(g_stage6_rbxm_file_manager_feature_registry_node));
  std::memset(g_stage6_rbxm_file_manager_feature_registry_buckets, 0,
              sizeof(g_stage6_rbxm_file_manager_feature_registry_buckets));
  WriteLibcxxString(g_stage6_rbxm_file_manager_feature_registry_node + 0x10,
                    kStage6UniversalAppRbxmUri);

  using FeatureRegistryHashFn = uintptr_t (*)(void*, const void*);
  auto* hash = reinterpret_cast<FeatureRegistryHashFn>(hash_address);
  const uintptr_t hash_value =
      hash(reinterpret_cast<void*>(registry_address + 0x18),
           g_stage6_rbxm_file_manager_feature_registry_node + 0x10);
  *reinterpret_cast<uintptr_t*>(
      g_stage6_rbxm_file_manager_feature_registry_node + 0x08) = hash_value;

  constexpr uintptr_t kBucketCount = 2;
  const uintptr_t bucket_index = hash_value & (kBucketCount - 1);
  g_stage6_rbxm_file_manager_feature_registry_buckets[bucket_index] =
      registry_address + 0x10;

  *reinterpret_cast<uintptr_t*>(registry_address + 0x00) =
      reinterpret_cast<uintptr_t>(
          g_stage6_rbxm_file_manager_feature_registry_buckets);
  *reinterpret_cast<uintptr_t*>(registry_address + 0x08) = kBucketCount;
  *reinterpret_cast<uintptr_t*>(registry_address + 0x10) =
      reinterpret_cast<uintptr_t>(
          g_stage6_rbxm_file_manager_feature_registry_node);
  *reinterpret_cast<uintptr_t*>(registry_address + 0x18) = 1;
  *reinterpret_cast<uint32_t*>(registry_address + 0x20) = 0x3f800000u;
  std::memset(mutex, 0, 0x90);

  char feature_registry_preview[520];
  ReadRbxmFileManagerFeatureRegistryPreview(libroblox_base,
                                            feature_registry_preview,
                                            sizeof(feature_registry_preview));
  std::cout
      << "  [patch] installed Stage6 RbxmFileManager feature registry fallback "
      << "uri=\"" << kStage6UniversalAppRbxmUri << "\" bucket=" << bucket_index
      << ' ' << feature_registry_preview << '\n'
      << std::flush;
  return true;
}

bool CallStage6RbxmInitWithRecovery(uintptr_t libroblox_base, uintptr_t offset,
                                    const char* label, const char* name,
                                    const unsigned char* expected_prologue,
                                    size_t expected_size,
                                    uintptr_t* out_result = nullptr) {
  if (out_result != nullptr) {
    *out_result = 0;
  }
  if (libroblox_base == 0 || name == nullptr) {
    return false;
  }

  auto* init_address =
      reinterpret_cast<unsigned char*>(libroblox_base + offset);
  if (expected_prologue == nullptr || expected_size == 0) {
    return false;
  }
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(init_address),
                             expected_size) ||
      std::memcmp(init_address, expected_prologue, expected_size) != 0) {
    std::cerr << "  [patch] Stage6 " << (label != nullptr ? label : "RBXM")
              << ' ' << name << " init signature mismatch at 0x" << std::hex
              << offset << std::dec << '\n'
              << std::flush;
    return false;
  }

  using InitFn = uintptr_t (*)();
  auto* init = reinterpret_cast<InitFn>(init_address);
  g_libroblox_ctor_recovered_signo = 0;
  g_libroblox_ctor_recovered_rip = 0;
  g_libroblox_ctor_recovered_si_addr = 0;
  if (sigsetjmp(g_libroblox_ctor_jmp_buf, 1) != 0) {
    DisarmLibRobloxConstructorAlarm();
    g_libroblox_ctor_recovery_in_progress = 0;
    uintptr_t rip = static_cast<uintptr_t>(g_libroblox_ctor_recovered_rip);
    uintptr_t rip_offset = (libroblox_base != 0 && rip >= libroblox_base &&
                            rip < libroblox_base + 0x08000000)
                               ? rip - libroblox_base
                               : 0;
    std::cout << "  [patch] Stage6 " << (label != nullptr ? label : "RBXM")
              << ' ' << name << " init recovered signal "
              << static_cast<int>(g_libroblox_ctor_recovered_signo)
              << " offset=0x" << std::hex << offset << " rip_off=0x"
              << rip_offset << " si_addr=0x"
              << static_cast<uintptr_t>(g_libroblox_ctor_recovered_si_addr)
              << std::dec << '\n'
              << std::flush;
    return false;
  }

  g_libroblox_ctor_recovery_in_progress = 1;
  ArmLibRobloxConstructorAlarm();
  const uintptr_t result = init();
  g_libroblox_ctor_recovery_in_progress = 0;
  DisarmLibRobloxConstructorAlarm();
  if (out_result != nullptr) {
    *out_result = result;
  }
  std::cout << "  [patch] Stage6 " << (label != nullptr ? label : "RBXM") << ' '
            << name << " init called at 0x" << std::hex << offset
            << " result=0x" << result << std::dec << '\n'
            << std::flush;
  return true;
}

bool CallStage6RbxmCoreClassInitWithRecovery(uintptr_t libroblox_base,
                                             uintptr_t offset, const char* name,
                                             uintptr_t* descriptor) {
  static constexpr unsigned char kExpectedInitPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x81, 0xec, 0xe8, 0x00, 0x00, 0x00,
  };
  return CallStage6RbxmInitWithRecovery(
      libroblox_base, offset, "RBXM core class registry", name,
      kExpectedInitPrologue, sizeof(kExpectedInitPrologue), descriptor);
}

void ReadRbxmClassDescriptorIndexPreview(uintptr_t descriptor, char* out,
                                         size_t out_size);

constexpr size_t kStage6RbxmMaxSeededPropertyDescriptors = 24;
struct Stage6RbxmPropertyGroupSeedStorage {
  uintptr_t descriptors[kStage6RbxmMaxSeededPropertyDescriptors];
  uintptr_t source_entry[2];
};

Stage6RbxmPropertyGroupSeedStorage g_stage6_rbxm_instance_property_group_seed;
uintptr_t g_stage6_rbxm_instance_static_descriptor_init_result = 0;
uintptr_t g_stage6_rbxm_string_type_descriptor = 0;
constexpr size_t kStage6RbxmNameDescriptorCacheSize = 8;
uintptr_t
    g_stage6_rbxm_name_descriptor_cache[kStage6RbxmNameDescriptorCacheSize] =
        {};

void CacheStage6RbxmNameDescriptor(uintptr_t descriptor) {
  if (descriptor == 0) {
    return;
  }
  for (uintptr_t cached : g_stage6_rbxm_name_descriptor_cache) {
    if (cached == descriptor) {
      return;
    }
  }
  for (uintptr_t& cached : g_stage6_rbxm_name_descriptor_cache) {
    if (cached == 0) {
      cached = descriptor;
      return;
    }
  }
}

bool IsCachedStage6RbxmNameDescriptor(uintptr_t descriptor) {
  if (descriptor == 0) {
    return false;
  }
  for (uintptr_t cached : g_stage6_rbxm_name_descriptor_cache) {
    if (cached == descriptor) {
      return true;
    }
  }
  return false;
}

bool RbxmDescriptorNameEquals(uintptr_t descriptor, const char* expected_name) {
  if (descriptor == 0 || expected_name == nullptr) {
    return false;
  }

  char name_preview[128];
  ReadRbxmDescriptorNameCandidate(descriptor, name_preview,
                                  sizeof(name_preview));
  const bool matches = std::strcmp(name_preview, expected_name) == 0;
  if (matches && std::strcmp(expected_name, "Name") == 0) {
    CacheStage6RbxmNameDescriptor(descriptor);
  }
  return matches;
}

bool IsLikelyCallableRbxmPropertyDescriptor(uintptr_t descriptor) {
  if (descriptor == 0 || !IsReadableMemoryRange(descriptor, 0x90)) {
    return false;
  }

  const uintptr_t vtable = ReadPointerIfReadable(descriptor);
  if (vtable == 0 || !IsReadableMemoryRange(vtable + 0xd0, sizeof(uintptr_t))) {
    return false;
  }

  const uintptr_t setter = ReadPointerIfReadable(vtable + 0xd0);
  return setter != 0 && IsExecutableMemoryRange(setter, 1);
}

void LogRbxmPropertyDescriptorCandidateReject(const char* expected_name,
                                              const char* source,
                                              uintptr_t candidate) {
  char resolved_name[128];
  ReadRbxmDescriptorNameCandidate(candidate, resolved_name,
                                  sizeof(resolved_name));
  const uintptr_t vtable = ReadPointerIfReadable(candidate);
  const uintptr_t setter = ReadPointerIfReadable(vtable + 0xd0);
  std::cout << "  [patch] Stage6 RBXM property descriptor reject "
            << "rbxm-property-descriptor-reject name=\""
            << (expected_name != nullptr ? expected_name : "")
            << "\" resolved_name=\"" << resolved_name << "\" source=\""
            << (source != nullptr ? source : "")
            << "\" candidate=" << reinterpret_cast<void*>(candidate)
            << " vtable=" << reinterpret_cast<void*>(vtable)
            << " setter=" << reinterpret_cast<void*>(setter)
            << " setter_executable="
            << (IsExecutableMemoryRange(setter, 1) ? 1 : 0) << '\n'
            << std::flush;
}

bool RbxmPropertyDescriptorNameEqualsAndCallable(uintptr_t descriptor,
                                                 const char* expected_name,
                                                 const char* source) {
  if (!RbxmDescriptorNameEquals(descriptor, expected_name)) {
    return false;
  }
  if (!IsLikelyCallableRbxmPropertyDescriptor(descriptor)) {
    LogRbxmPropertyDescriptorCandidateReject(expected_name, source, descriptor);
    return false;
  }
  return true;
}

uintptr_t FindRbxmDescriptorByNameInStaticGlobals(uintptr_t libroblox_base,
                                                  const char* name) {
  if (libroblox_base == 0 || name == nullptr || name[0] == '\0') {
    return 0;
  }

  const uintptr_t ranges[][2] = {
      {kStage6RbxmInstanceStaticDescriptorObjectsStartOffset,
       kStage6RbxmInstanceStaticDescriptorObjectsEndOffset},
      {kStage6RbxmInstanceStaticDescriptorGlobalsStartOffset,
       kStage6RbxmInstanceStaticDescriptorGlobalsEndOffset},
  };
  for (const auto& range : ranges) {
    for (uintptr_t offset = range[0]; offset < range[1];
         offset += sizeof(uintptr_t)) {
      const uintptr_t address = libroblox_base + offset;
      if (RbxmPropertyDescriptorNameEqualsAndCallable(
              address, name, "static-global-address")) {
        return address;
      }
      const uintptr_t candidate = ReadPointerIfReadable(address);
      if (RbxmPropertyDescriptorNameEqualsAndCallable(
              candidate, name, "static-global-pointer")) {
        return candidate;
      }
    }
  }

  return 0;
}

uintptr_t FindRbxmDescriptorByNameInRegistry(uintptr_t libroblox_base,
                                             const char* name) {
  if (libroblox_base == 0 || name == nullptr || name[0] == '\0') {
    return 0;
  }

  if (RbxmPropertyDescriptorNameEqualsAndCallable(
          g_stage6_rbxm_instance_static_descriptor_init_result, name,
          "instance-static-descriptor-init-result")) {
    return g_stage6_rbxm_instance_static_descriptor_init_result;
  }

  const uintptr_t static_descriptor =
      FindRbxmDescriptorByNameInStaticGlobals(libroblox_base, name);
  if (static_descriptor != 0) {
    return static_descriptor;
  }

  const uintptr_t registry_globals[] = {
      libroblox_base + kStage6RbxmPrimaryDescriptorRegistryHeadGlobalOffset,
      libroblox_base + kStage6RbxmSecondaryDescriptorRegistryHeadGlobalOffset,
  };
  for (uintptr_t registry_global : registry_globals) {
    uintptr_t node = ReadPointerIfReadable(registry_global);
    for (size_t node_count = 0;
         node != 0 && node_count < 4096 &&
         IsReadableMemoryRange(node, sizeof(uintptr_t) * 2);
         ++node_count) {
      for (uintptr_t field_offset = 0x10; field_offset <= 0x80;
           field_offset += sizeof(uintptr_t)) {
        const uintptr_t candidate = ReadPointerIfReadable(node + field_offset);
        if (RbxmPropertyDescriptorNameEqualsAndCallable(
                candidate, name, "descriptor-registry-node")) {
          return candidate;
        }
      }

      const uintptr_t next = ReadPointerIfReadable(node + sizeof(uintptr_t));
      if (next == node) {
        break;
      }
      node = next;
    }
  }

  return 0;
}

bool PromoteStage6RbxmSeedDescriptorForRbxmApply(uintptr_t libroblox_base,
                                                 uintptr_t descriptor,
                                                 const char* descriptor_name) {
  if (libroblox_base == 0 || descriptor == 0 || descriptor_name == nullptr ||
      std::strcmp(descriptor_name, "Name") != 0) {
    return false;
  }
  CacheStage6RbxmNameDescriptor(descriptor);

  uintptr_t string_type_descriptor =
      libroblox_base + kStage6RbxmStringTypeDescriptorStaticOffset;
  uintptr_t string_type_init_result = 0;
  static constexpr unsigned char kExpectedStringTypePrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x53, 0x50, 0x8a, 0x05,
  };
  if (CallStage6RbxmInitWithRecovery(
          libroblox_base, kStage6RbxmStringTypeDescriptorInitOffset,
          "RBXM property type", "string", kExpectedStringTypePrologue,
          sizeof(kExpectedStringTypePrologue), &string_type_init_result) &&
      string_type_init_result != 0) {
    string_type_descriptor = string_type_init_result;
  }
  g_stage6_rbxm_string_type_descriptor = string_type_descriptor;

  constexpr unsigned char kRbxmApplyFlag = 0x04;
  const uintptr_t flag_address = descriptor + 0x87;
  const uintptr_t type_address = descriptor + 0x60;
  if (!IsReadableMemoryRange(flag_address, 1)) {
    std::cout << "  [patch] Stage6 RBXM property descriptor promote "
              << "rbxm-property-descriptor-promote name=\"" << descriptor_name
              << "\" descriptor=" << reinterpret_cast<void*>(descriptor)
              << " flag87_unreadable\n"
              << std::flush;
    return false;
  }

  const unsigned char old_flag =
      *reinterpret_cast<const unsigned char*>(flag_address);
  const unsigned char new_flag = old_flag | kRbxmApplyFlag;
  bool promoted = false;
  const uintptr_t old_type = ReadPointerIfReadable(type_address);
  bool type_promoted = false;
  if (string_type_descriptor != 0 && old_type != string_type_descriptor) {
    if (!EnsureWritablePage(reinterpret_cast<void*>(type_address))) {
      std::cout << "  [patch] Stage6 RBXM property descriptor promote "
                << "rbxm-property-descriptor-promote name=\"" << descriptor_name
                << "\" descriptor=" << reinterpret_cast<void*>(descriptor)
                << " type_mprotect_failed errno=" << errno << '\n'
                << std::flush;
      return false;
    }
    *reinterpret_cast<uintptr_t*>(type_address) = string_type_descriptor;
    type_promoted = true;
  }
  if (old_flag != new_flag) {
    if (!EnsureWritablePage(reinterpret_cast<void*>(flag_address))) {
      std::cout << "  [patch] Stage6 RBXM property descriptor promote "
                << "rbxm-property-descriptor-promote name=\"" << descriptor_name
                << "\" descriptor=" << reinterpret_cast<void*>(descriptor)
                << " mprotect_failed errno=" << errno << '\n'
                << std::flush;
      return false;
    }
    *reinterpret_cast<unsigned char*>(flag_address) = new_flag;
    promoted = true;
  }

  char resolved_name[128];
  ReadRbxmDescriptorNameCandidate(descriptor, resolved_name,
                                  sizeof(resolved_name));
  const unsigned char final_flag =
      IsReadableMemoryRange(flag_address, 1)
          ? *reinterpret_cast<const unsigned char*>(flag_address)
          : 0xffu;
  std::cout << "  [patch] Stage6 RBXM property descriptor promote "
            << "rbxm-property-descriptor-promote name=\"" << descriptor_name
            << "\" resolved_name=\"" << resolved_name
            << "\" descriptor=" << reinterpret_cast<void*>(descriptor)
            << " type_old=" << reinterpret_cast<void*>(old_type) << " type_new="
            << reinterpret_cast<void*>(ReadPointerIfReadable(descriptor + 0x60))
            << " string_type="
            << reinterpret_cast<void*>(string_type_descriptor)
            << " type_promoted=" << (type_promoted ? 1 : 0) << " flag87_old=0x"
            << std::hex << static_cast<unsigned int>(old_flag)
            << " flag87_new=0x" << static_cast<unsigned int>(final_flag)
            << std::dec << " promoted=" << (promoted ? 1 : 0) << '\n'
            << std::flush;
  return true;
}

bool RepairStage6RbxmNameDescriptorForRbxmApply(uintptr_t descriptor,
                                                const char* reason) {
  constexpr unsigned char kRbxmApplyFlag = 0x04;
  const uintptr_t string_type_descriptor = g_stage6_rbxm_string_type_descriptor;
  if (descriptor == 0 || string_type_descriptor == 0) {
    return false;
  }
  CacheStage6RbxmNameDescriptor(descriptor);

  const uintptr_t type_address = descriptor + 0x60;
  const uintptr_t flag_address = descriptor + 0x87;
  if (!IsReadableMemoryRange(type_address, sizeof(uintptr_t)) ||
      !IsReadableMemoryRange(flag_address, 1)) {
    return false;
  }

  const uintptr_t old_type = ReadPointerIfReadable(type_address);
  const unsigned char old_flag =
      *reinterpret_cast<const unsigned char*>(flag_address);
  bool type_repaired = false;
  bool flag_repaired = false;
  if (old_type != string_type_descriptor &&
      EnsureWritablePage(reinterpret_cast<void*>(type_address))) {
    *reinterpret_cast<uintptr_t*>(type_address) = string_type_descriptor;
    type_repaired = true;
  }
  if ((old_flag & kRbxmApplyFlag) == 0 &&
      EnsureWritablePage(reinterpret_cast<void*>(flag_address))) {
    *reinterpret_cast<unsigned char*>(flag_address) = old_flag | kRbxmApplyFlag;
    flag_repaired = true;
  }

  if (type_repaired || flag_repaired) {
    const uintptr_t final_type = ReadPointerIfReadable(type_address);
    const unsigned int final_flag =
        IsReadableMemoryRange(flag_address, 1)
            ? *reinterpret_cast<const unsigned char*>(flag_address)
            : 0xffu;
    char msg[700];
    int len = std::snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 RBXM Name descriptor live repair "
        "name-descriptor-live-repair reason=%s descriptor=%p "
        "type_old=%p type_new=%p string_type=%p type_repaired=%d "
        "flag87_old=0x%x flag87_new=0x%x flag_repaired=%d\n",
        reason != nullptr ? reason : "", reinterpret_cast<void*>(descriptor),
        reinterpret_cast<void*>(old_type), reinterpret_cast<void*>(final_type),
        reinterpret_cast<void*>(string_type_descriptor), type_repaired ? 1 : 0,
        static_cast<unsigned int>(old_flag), final_flag, flag_repaired ? 1 : 0);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  return type_repaired || flag_repaired;
}

bool AppendRbxmSeedDescriptor(uintptr_t libroblox_base,
                              const char* descriptor_name,
                              Stage6RbxmPropertyGroupSeedStorage* storage,
                              size_t* count) {
  if (storage == nullptr || count == nullptr ||
      *count >= kStage6RbxmMaxSeededPropertyDescriptors) {
    return false;
  }

  const uintptr_t descriptor =
      FindRbxmDescriptorByNameInRegistry(libroblox_base, descriptor_name);
  if (descriptor == 0) {
    std::cout << "  [patch] Stage6 RBXM property group seed "
              << "rbxm-property-group-seed missing_descriptor=\""
              << (descriptor_name != nullptr ? descriptor_name : "") << "\"\n"
              << std::flush;
    return false;
  }

  PromoteStage6RbxmSeedDescriptorForRbxmApply(libroblox_base, descriptor,
                                              descriptor_name);

  for (size_t index = 0; index < *count; ++index) {
    if (storage->descriptors[index] == descriptor) {
      return true;
    }
  }
  storage->descriptors[*count] = descriptor;
  ++(*count);
  return true;
}

bool SeedStage6RbxmClassPropertyGroup(
    uintptr_t libroblox_base, uintptr_t class_descriptor,
    const char* class_name, Stage6RbxmPropertyGroupSeedStorage* storage) {
  if (libroblox_base == 0 || class_descriptor == 0 || class_name == nullptr ||
      storage == nullptr ||
      !IsEnabled("MOCKTAIL_SEED_STAGE6_RBXM_PROPERTY_GROUPS")) {
    return false;
  }
  if (!IsReadableMemoryRange(class_descriptor, 0x2a9)) {
    std::cout << "  [patch] Stage6 RBXM property group seed "
              << "rbxm-property-group-seed class=\"" << class_name
              << "\" descriptor_unreadable\n"
              << std::flush;
    return false;
  }

  if (std::strcmp(class_name, "Instance") != 0) {
    return false;
  }

  std::memset(storage, 0, sizeof(*storage));
  size_t count = 0;
  AppendRbxmSeedDescriptor(libroblox_base, "Name", storage, &count);
  AppendRbxmSeedDescriptor(libroblox_base, "Archivable", storage, &count);
  AppendRbxmSeedDescriptor(libroblox_base, "Attributes", storage, &count);
  AppendRbxmSeedDescriptor(libroblox_base, "HistoryId", storage, &count);
  AppendRbxmSeedDescriptor(libroblox_base, "SourceAssetId", storage, &count);
  AppendRbxmSeedDescriptor(libroblox_base, "numExpectedDirectChildren", storage,
                           &count);
  if (count == 0) {
    return false;
  }

  const uintptr_t group = class_descriptor + 0x28;
  if (!EnsureWritablePage(reinterpret_cast<void*>(group))) {
    std::cout << "  [patch] Stage6 RBXM property group seed "
              << "rbxm-property-group-seed class=\"" << class_name
              << "\" mprotect_failed errno=" << errno << '\n'
              << std::flush;
    return false;
  }

  storage->source_entry[0] = reinterpret_cast<uintptr_t>(storage->descriptors);
  storage->source_entry[1] = count;
  const uintptr_t source_entry =
      reinterpret_cast<uintptr_t>(storage->source_entry);
  *reinterpret_cast<uintptr_t*>(group + 0x00) = source_entry;
  *reinterpret_cast<uintptr_t*>(group + 0x08) =
      source_entry + sizeof(storage->source_entry);
  *reinterpret_cast<uintptr_t*>(group + 0x10) =
      source_entry + sizeof(storage->source_entry);
  *reinterpret_cast<uintptr_t*>(group + 0x28) = count;
  *reinterpret_cast<unsigned char*>(group + 0x58) = 0;

  char preview[560];
  ReadRbxmClassDescriptorIndexPreview(class_descriptor, preview,
                                      sizeof(preview));
  std::cout << "  [patch] Stage6 RBXM property group seed "
            << "rbxm-property-group-seed class=\"" << class_name
            << "\" count=" << count
            << " group=" << reinterpret_cast<void*>(group)
            << " descriptors=" << reinterpret_cast<void*>(storage->descriptors)
            << " preview={" << preview << "}\n"
            << std::flush;
  return true;
}

void ReadRbxmClassDescriptorIndexPreview(uintptr_t descriptor, char* out,
                                         size_t out_size) {
  if (out == nullptr || out_size == 0) {
    return;
  }
  if (!IsReadableMemoryRange(descriptor, 0x2a9)) {
    std::snprintf(out, out_size, "descriptor-unreadable");
    return;
  }

  const uint32_t combined_count = ReadU32IfReadable(descriptor + 0x248);
  const uint32_t property_vector_count0 = ReadU32IfReadable(descriptor + 0x50);
  const uint32_t property_vector_count1 = ReadU32IfReadable(descriptor + 0xb0);
  const uint32_t property_vector_count2 = ReadU32IfReadable(descriptor + 0x110);
  const uint32_t property_vector_count3 = ReadU32IfReadable(descriptor + 0x170);
  const uint32_t property_vector_count4 = ReadU32IfReadable(descriptor + 0x1d0);
  const uint32_t property_source_count =
      property_vector_count0 + property_vector_count1 + property_vector_count2 +
      property_vector_count3 + property_vector_count4;
  const uint32_t property_count = ReadU32IfReadable(descriptor + 0x278);
  const uint32_t property_capacity = ReadU32IfReadable(descriptor + 0x27c);
  const uintptr_t property_buckets = ReadPointerIfReadable(descriptor + 0x280);
  const uintptr_t property_entries = ReadPointerIfReadable(descriptor + 0x288);
  const uint32_t property_mask = ReadU32IfReadable(descriptor + 0x290);
  const uint32_t property_shift = ReadU32IfReadable(descriptor + 0x294);
  const unsigned int property_index_ready =
      IsReadableMemoryRange(descriptor + 0x2a8, 1)
          ? *reinterpret_cast<const unsigned char*>(descriptor + 0x2a8)
          : 0xffu;
  std::snprintf(out, out_size,
                "descriptor_vectors property_vector_counts=%u/%u/%u/%u/%u "
                "property_source_count=%u combined_count=%u property_count=%u "
                "property_capacity=%u "
                "property_buckets=%p property_entries=%p property_mask=0x%x "
                "property_shift=0x%x ready=0x%x",
                property_vector_count0, property_vector_count1,
                property_vector_count2, property_vector_count3,
                property_vector_count4, property_source_count, combined_count,
                property_count, property_capacity,
                reinterpret_cast<void*>(property_buckets),
                reinterpret_cast<void*>(property_entries), property_mask,
                property_shift, property_index_ready);
}

bool CallStage6RbxmClassDescriptorIndexBuildWithRecovery(
    uintptr_t libroblox_base, uintptr_t descriptor, const char* name) {
  if (libroblox_base == 0 || descriptor == 0 || name == nullptr ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_RBXM_CLASS_DESCRIPTOR_INDEX")) {
    return false;
  }
  if (!IsReadableMemoryRange(descriptor, 0x2a9)) {
    std::cerr << "  [patch] Stage6 RBXM class descriptor index build " << name
              << " descriptor is unreadable: "
              << reinterpret_cast<void*>(descriptor) << '\n'
              << std::flush;
    return false;
  }

  auto* build_address = reinterpret_cast<unsigned char*>(
      libroblox_base + kStage6RbxmClassDescriptorIndexBuildOffset);
  static constexpr unsigned char kExpectedIndexBuildPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
      0x41, 0x54, 0x53, 0x48, 0x81, 0xec, 0x98, 0x00, 0x00, 0x00,
  };
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(build_address),
                             sizeof(kExpectedIndexBuildPrologue)) ||
      std::memcmp(build_address, kExpectedIndexBuildPrologue,
                  sizeof(kExpectedIndexBuildPrologue)) != 0) {
    std::cerr << "  [patch] Stage6 RBXM class descriptor index build " << name
              << " signature mismatch at 0x" << std::hex
              << kStage6RbxmClassDescriptorIndexBuildOffset << std::dec << '\n'
              << std::flush;
    return false;
  }

  char before_preview[560];
  ReadRbxmClassDescriptorIndexPreview(descriptor, before_preview,
                                      sizeof(before_preview));

  using IndexBuildFn = void (*)(void*);
  auto* build = reinterpret_cast<IndexBuildFn>(build_address);
  g_libroblox_ctor_recovered_signo = 0;
  g_libroblox_ctor_recovered_rip = 0;
  g_libroblox_ctor_recovered_si_addr = 0;
  if (sigsetjmp(g_libroblox_ctor_jmp_buf, 1) != 0) {
    DisarmLibRobloxConstructorAlarm();
    g_libroblox_ctor_recovery_in_progress = 0;
    uintptr_t rip = static_cast<uintptr_t>(g_libroblox_ctor_recovered_rip);
    uintptr_t rip_offset = (libroblox_base != 0 && rip >= libroblox_base &&
                            rip < libroblox_base + 0x08000000)
                               ? rip - libroblox_base
                               : 0;
    std::cout << "  [patch] Stage6 RBXM class descriptor index build " << name
              << " recovered signal "
              << static_cast<int>(g_libroblox_ctor_recovered_signo)
              << " descriptor=" << reinterpret_cast<void*>(descriptor)
              << " rip_off=0x" << std::hex << rip_offset << " si_addr=0x"
              << static_cast<uintptr_t>(g_libroblox_ctor_recovered_si_addr)
              << std::dec << " before={" << before_preview << "}\n"
              << std::flush;
    return false;
  }

  g_libroblox_ctor_recovery_in_progress = 1;
  ArmLibRobloxConstructorAlarm();
  build(reinterpret_cast<void*>(descriptor));
  g_libroblox_ctor_recovery_in_progress = 0;
  DisarmLibRobloxConstructorAlarm();

  char after_preview[560];
  ReadRbxmClassDescriptorIndexPreview(descriptor, after_preview,
                                      sizeof(after_preview));
  const bool indexed = ReadU32IfReadable(descriptor + 0x278) != 0;
  std::cout << "  [patch] Stage6 RBXM class descriptor index build "
            << "rbxm-class-descriptor-index " << name
            << " descriptor=" << reinterpret_cast<void*>(descriptor)
            << " indexed=" << (indexed ? 1 : 0) << " before={" << before_preview
            << "} after={" << after_preview << "}\n"
            << std::flush;
  return indexed;
}

bool CallStage6RbxmInstanceStaticDescriptorInitWithRecovery(
    uintptr_t libroblox_base) {
  const bool seed_stage6_rbxm_property_groups =
      IsEnabled("MOCKTAIL_SEED_STAGE6_RBXM_PROPERTY_GROUPS");
  if (libroblox_base == 0 ||
      (!IsEnabled(
           "MOCKTAIL_CALL_STAGE6_RBXM_INSTANCE_STATIC_DESCRIPTOR_INIT") &&
       !seed_stage6_rbxm_property_groups)) {
    return false;
  }

  static constexpr unsigned char kExpectedStaticDescriptorPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x56, 0x53, 0x48, 0x83, 0xec, 0x20,
  };
  uintptr_t result = 0;
  const bool called = CallStage6RbxmInitWithRecovery(
      libroblox_base, kStage6RbxmInstanceStaticDescriptorInitOffset,
      "RBXM static descriptor", "InstanceStaticDescriptors",
      kExpectedStaticDescriptorPrologue,
      sizeof(kExpectedStaticDescriptorPrologue), &result);
  g_stage6_rbxm_instance_static_descriptor_init_result = result;
  char result_name[128];
  ReadRbxmDescriptorNameCandidate(result, result_name, sizeof(result_name));
  std::cout << "  [patch] Stage6 RBXM static descriptor init "
            << "rbxm-static-descriptor-init InstanceStaticDescriptors "
            << "called=" << (called ? 1 : 0) << " offset=0x" << std::hex
            << kStage6RbxmInstanceStaticDescriptorInitOffset << " result=0x"
            << result << std::dec << " result_name=\"" << result_name << "\"\n"
            << std::flush;
  return called;
}

bool InstallStage6RbxmCoreClassRegistryFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_RBXM_CORE_CLASS_REGISTRY")) {
    return false;
  }

  const uintptr_t registry =
      libroblox_base + kStage6RbxmCoreClassRegistryGlobalOffset;
  if (!IsReadableMemoryRange(registry, 0x38)) {
    std::cerr << "  [patch] Stage6 RBXM core class registry global "
              << "is unreadable\n"
              << std::flush;
    return false;
  }

  InstallLibRobloxConstructorAlarm();
  char before_preview[420];
  ReadRbxmCoreClassRegistryPreview(libroblox_base, before_preview,
                                   sizeof(before_preview));

  struct ClassInit {
    uintptr_t offset;
    const char* name;
  };
  constexpr ClassInit kClassInits[] = {
      {kStage6RbxmInstanceClassInitOffset, "Instance"},
      {kStage6RbxmFolderClassInitOffset, "Folder"},
      {kStage6RbxmModuleScriptClassInitOffset, "ModuleScript"},
      {kStage6RbxmStringValueClassInitOffset, "StringValue"},
  };

  bool called_all = true;
  bool indexed_all = true;
  for (const auto& entry : kClassInits) {
    uintptr_t descriptor = 0;
    const bool called = CallStage6RbxmCoreClassInitWithRecovery(
        libroblox_base, entry.offset, entry.name, &descriptor);
    if (called) {
      SeedStage6RbxmClassPropertyGroup(
          libroblox_base, descriptor, entry.name,
          &g_stage6_rbxm_instance_property_group_seed);
    }
    const bool indexed =
        called && CallStage6RbxmClassDescriptorIndexBuildWithRecovery(
                      libroblox_base, descriptor, entry.name);
    called_all = called && called_all;
    indexed_all = indexed && indexed_all;
  }

  char after_preview[420];
  ReadRbxmCoreClassRegistryPreview(libroblox_base, after_preview,
                                   sizeof(after_preview));
  const bool initialized = ReadPointerIfReadable(registry + 0x00) != 0 ||
                           ReadPointerIfReadable(registry + 0x08) != 0 ||
                           ReadPointerIfReadable(registry + 0x10) != 0 ||
                           ReadPointerIfReadable(registry + 0x18) != 0;
  std::cout << "  [patch] installed Stage6 RBXM core class registry fallback "
            << "called_all=" << (called_all ? 1 : 0)
            << " indexed_all=" << (indexed_all ? 1 : 0)
            << " initialized=" << (initialized ? 1 : 0)
            << " before=" << before_preview << " after=" << after_preview
            << '\n'
            << std::flush;
  return initialized && called_all && indexed_all;
}

bool InstallStage6RbxmReflectionDescriptorFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled(
          "MOCKTAIL_INSTALL_STAGE6_RBXM_REFLECTION_DESCRIPTOR_FALLBACK")) {
    return false;
  }

  InstallLibRobloxConstructorAlarm();
  static constexpr unsigned char kInstanceReflectionPrologue[] = {
      0x55, 0x48, 0x89, 0xe5, 0x53, 0x50, 0x8a, 0x05,
  };
  static constexpr unsigned char kReflectionPrologueStack98[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
      0x53, 0x48, 0x81, 0xec, 0x98, 0x00, 0x00, 0x00,
  };
  static constexpr unsigned char kReflectionPrologueStackA8[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56,
      0x53, 0x48, 0x81, 0xec, 0xa8, 0x00, 0x00, 0x00,
  };
  static constexpr unsigned char kReflectionPrologueStack208[] = {
      0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55,
      0x41, 0x54, 0x53, 0x48, 0x81, 0xec, 0x08, 0x02, 0x00, 0x00,
  };

  struct ReflectionInit {
    uintptr_t offset;
    const char* name;
    const unsigned char* expected_prologue;
    size_t expected_size;
  };
  constexpr ReflectionInit kReflectionInits[] = {
      {kStage6RbxmInstanceReflectionInitOffset, "Instance",
       kInstanceReflectionPrologue, sizeof(kInstanceReflectionPrologue)},
      {kStage6RbxmInstancePropertyDescriptorInitOffset, "InstanceProperties",
       kReflectionPrologueStack208, sizeof(kReflectionPrologueStack208)},
      {kStage6RbxmFolderReflectionInitOffset, "Folder",
       kReflectionPrologueStack98, sizeof(kReflectionPrologueStack98)},
      {kStage6RbxmModuleScriptReflectionInitOffset, "ModuleScript",
       kReflectionPrologueStack98, sizeof(kReflectionPrologueStack98)},
      {kStage6RbxmStringValueReflectionInitOffset, "StringValue",
       kReflectionPrologueStackA8, sizeof(kReflectionPrologueStackA8)},
  };

  char registry_preview[kStage6RbxmDescriptorRegistryPreviewSize];
  ReadRbxmDescriptorRegistryPreview(libroblox_base, registry_preview,
                                    sizeof(registry_preview));
  std::cout << "  [patch] Stage6 RBXM descriptor registry "
            << "rbxm-descriptor-registry before=" << registry_preview << '\n'
            << std::flush;

  bool called_all = true;
  for (const auto& entry : kReflectionInits) {
    const bool called = CallStage6RbxmInitWithRecovery(
        libroblox_base, entry.offset, "RBXM reflection descriptor", entry.name,
        entry.expected_prologue, entry.expected_size);
    called_all = called && called_all;
    ReadRbxmDescriptorRegistryPreview(libroblox_base, registry_preview,
                                      sizeof(registry_preview));
    std::cout << "  [patch] Stage6 RBXM descriptor registry "
              << "rbxm-descriptor-registry after_" << entry.name
              << " called=" << (called ? 1 : 0) << ' ' << registry_preview
              << '\n'
              << std::flush;
  }
  const bool instance_static_descriptor_called =
      CallStage6RbxmInstanceStaticDescriptorInitWithRecovery(libroblox_base);
  ReadRbxmDescriptorRegistryPreview(libroblox_base, registry_preview,
                                    sizeof(registry_preview));
  std::cout << "  [patch] Stage6 RBXM descriptor registry "
            << "rbxm-descriptor-registry after_InstanceStaticDescriptors "
            << "called=" << (instance_static_descriptor_called ? 1 : 0) << ' '
            << registry_preview << '\n'
            << std::flush;

  std::cout << "  [patch] installed Stage6 RBXM reflection descriptor fallback "
            << "rbxm-reflection-descriptor called_all=" << (called_all ? 1 : 0)
            << " instance_static_descriptor_called="
            << (instance_static_descriptor_called ? 1 : 0) << '\n'
            << std::flush;
  return called_all;
}

bool InstallSkippedRobloxHeadlessSingletonFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_HEADLESS_SINGLETON_FALLBACK")) {
    return false;
  }

  auto** slot = reinterpret_cast<void**>(libroblox_base +
                                         kRobloxHeadlessSingletonGlobalOffset);
  if (*slot != nullptr) {
    return true;
  }

  std::memset(g_headless_singleton_backing, 0,
              sizeof(g_headless_singleton_backing));
  auto write_u32 = [](uintptr_t offset, uint32_t value) {
    std::memcpy(g_headless_singleton_backing + offset, &value, sizeof(value));
  };

  constexpr uint32_t kOneFloatBits = 0x3f800000;
  constexpr uintptr_t kFloatDefaultOffsets[] = {
      0x20,  0x88,  0xb0,  0xd8,  0x100, 0x128, 0x150, 0x178, 0x1a0,
      0x1c8, 0x1f0, 0x218, 0x240, 0x268, 0x290, 0x2b8, 0x300,
  };
  for (uintptr_t offset : kFloatDefaultOffsets) {
    write_u32(offset, kOneFloatBits);
  }
  std::memset(g_headless_singleton_backing + 0x50, 0xff, 0x10);
  write_u32(0x60, 0xffffffffu);
  g_headless_singleton_backing[0x2dc] = 1;

  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size > 0) {
    uintptr_t address = reinterpret_cast<uintptr_t>(slot);
    uintptr_t page = address & ~(static_cast<uintptr_t>(page_size) - 1);
    if (mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(page_size),
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
      std::cerr << "  [patch] headless singleton global mprotect failed: "
                << std::strerror(errno) << '\n'
                << std::flush;
      return false;
    }
  }

  *slot = g_headless_singleton_backing;
  std::cout << "  [patch] installed skipped Roblox headless singleton "
            << "fallback at 0x" << std::hex
            << kRobloxHeadlessSingletonGlobalOffset << std::dec
            << " ptr=" << static_cast<void*>(g_headless_singleton_backing)
            << '\n'
            << std::flush;
  return true;
}

bool InstallStage6SystemDialogSingletonGuardFallback(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_SYSTEM_DIALOG_SINGLETON_GUARD")) {
    return false;
  }

  auto** guard_slot = reinterpret_cast<uintptr_t**>(
      libroblox_base + kStage6SystemDialogSingletonGuardPointerGlobalOffset);
  auto** object_slot = reinterpret_cast<void**>(
      libroblox_base + kStage6SystemDialogSingletonObjectGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(guard_slot),
                             sizeof(*guard_slot)) ||
      !IsReadableMemoryRange(reinterpret_cast<uintptr_t>(object_slot),
                             sizeof(*object_slot))) {
    std::cerr << "  [patch] Stage6 system-dialog singleton globals are "
              << "unreadable\n"
              << std::flush;
    return false;
  }

  if (*guard_slot != nullptr) {
    return true;
  }

  g_stage6_system_dialog_singleton_guard = 0;
  if (!EnsureWritablePage(guard_slot)) {
    std::cerr << "  [patch] Stage6 system-dialog singleton guard global "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  *guard_slot = &g_stage6_system_dialog_singleton_guard;
  std::cout
      << "  [patch] installed Stage6 system-dialog singleton guard fallback "
      << "at 0x" << std::hex
      << kStage6SystemDialogSingletonGuardPointerGlobalOffset << std::dec
      << " guard="
      << static_cast<void*>(&g_stage6_system_dialog_singleton_guard)
      << " object=" << *object_slot << '\n'
      << std::flush;
  return true;
}

bool InstallStage6SystemDialogDependencySingletonGuardFallback(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled(
          "MOCKTAIL_INSTALL_STAGE6_SYSTEM_DIALOG_DEPENDENCY_SINGLETON_GUARD")) {
    return false;
  }

  auto** guard_slot = reinterpret_cast<uintptr_t**>(
      libroblox_base +
      kStage6SystemDialogDependencySingletonGuardPointerGlobalOffset);
  auto** object_slot = reinterpret_cast<void**>(
      libroblox_base +
      kStage6SystemDialogDependencySingletonObjectGlobalOffset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(guard_slot),
                             sizeof(*guard_slot)) ||
      !IsReadableMemoryRange(reinterpret_cast<uintptr_t>(object_slot),
                             sizeof(*object_slot))) {
    std::cerr << "  [patch] Stage6 system-dialog dependency singleton globals "
              << "are unreadable\n"
              << std::flush;
    return false;
  }

  if (*guard_slot != nullptr) {
    return true;
  }

  g_stage6_system_dialog_dependency_singleton_guard = 0;
  if (!EnsureWritablePage(guard_slot)) {
    std::cerr
        << "  [patch] Stage6 system-dialog dependency singleton guard global "
        << "mprotect failed: " << std::strerror(errno) << '\n'
        << std::flush;
    return false;
  }

  *guard_slot = &g_stage6_system_dialog_dependency_singleton_guard;
  std::cout << "  [patch] installed Stage6 system-dialog dependency singleton "
               "guard fallback "
            << "at 0x" << std::hex
            << kStage6SystemDialogDependencySingletonGuardPointerGlobalOffset
            << std::dec << " guard="
            << static_cast<void*>(
                   &g_stage6_system_dialog_dependency_singleton_guard)
            << " object=" << *object_slot << '\n'
            << std::flush;
  return true;
}

bool InstallStage6SystemDialogDescriptorFallbacks(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_SYSTEM_DIALOG_DESCRIPTORS")) {
    return false;
  }

  const uintptr_t chain =
      libroblox_base + kStage6SystemDialogDescriptorChainGlobalOffset;
  if (!IsReadableMemoryRange(chain, 0x80)) {
    std::cerr << "  [patch] Stage6 system-dialog descriptor globals are "
              << "unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(chain))) {
    std::cerr << "  [patch] Stage6 system-dialog descriptor global "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  const uintptr_t descriptor =
      libroblox_base + kStage6SystemDialogDescriptorPrimaryGlobalOffset;
  *reinterpret_cast<uintptr_t*>(descriptor + 0x00) =
      libroblox_base + kStage6SystemDialogDescriptorPrimaryNameOffset;
  *reinterpret_cast<uintptr_t*>(descriptor + 0x08) =
      libroblox_base + kStage6SystemDialogDescriptorDefaultNameOffset;
  *reinterpret_cast<uintptr_t*>(descriptor + 0x10) =
      libroblox_base + kStage6SystemDialogDescriptorPrimaryParentGlobalOffset;

  auto write_relative_pointer = [libroblox_base](uintptr_t slot_offset,
                                                 uintptr_t target_offset) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + slot_offset) =
        libroblox_base + target_offset;
  };

  write_relative_pointer(kStage6SystemDialogDescriptorChainGlobalOffset,
                         0x71c3ce0);
  write_relative_pointer(0x71c3d28, 0x22d8a86);
  write_relative_pointer(0x71c3d30, 0x71c3cf8);
  write_relative_pointer(0x71c3d38,
                         kStage6SystemDialogDescriptorSecondaryNameOffset);
  write_relative_pointer(0x71c3d40,
                         kStage6SystemDialogDescriptorDefaultNameOffset);
  write_relative_pointer(0x71c3d48, 0x71c3d20);
  write_relative_pointer(0x71c3d58,
                         kStage6SystemDialogDescriptorCallbackOffset);
  write_relative_pointer(0x71c3d60, 0x71c3d28);
  write_relative_pointer(0x71c3d68,
                         kStage6SystemDialogDescriptorHashNameOffset);
  write_relative_pointer(0x71c3d70,
                         kStage6SystemDialogDescriptorDefaultNameOffset);
  write_relative_pointer(0x71c3d78, 0x71c3d50);

  std::cout << "  [patch] installed Stage6 system-dialog descriptor fallback "
            << "at 0x" << std::hex
            << kStage6SystemDialogDescriptorPrimaryGlobalOffset << std::dec
            << " name=0x" << std::hex
            << kStage6SystemDialogDescriptorPrimaryNameOffset << std::dec
            << '\n'
            << std::flush;
  return true;
}

bool InstallStage6IxpDescriptorFallbacks(uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled("MOCKTAIL_INSTALL_STAGE6_IXP_DESCRIPTORS")) {
    return false;
  }

  const uintptr_t ixp_descriptor =
      libroblox_base + kStage6IxpDescriptorPrimaryGlobalOffset;
  if (!IsReadableMemoryRange(ixp_descriptor, 0x60)) {
    std::cerr << "  [patch] Stage6 IXP descriptor globals are unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(ixp_descriptor))) {
    std::cerr << "  [patch] Stage6 IXP descriptor global mprotect failed: "
              << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  *reinterpret_cast<uintptr_t*>(ixp_descriptor + 0x00) =
      libroblox_base + kStage6IxpDescriptorPrimaryNameOffset;
  *reinterpret_cast<uintptr_t*>(ixp_descriptor + 0x08) =
      libroblox_base + kStage6IxpDescriptorDefaultNameOffset;

  auto write_ixp_descriptor = [libroblox_base](uintptr_t descriptor_offset,
                                               uintptr_t name_offset) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + descriptor_offset + 0x00) =
        libroblox_base + name_offset;
    *reinterpret_cast<uintptr_t*>(libroblox_base + descriptor_offset + 0x08) =
        libroblox_base + kStage6IxpDescriptorDefaultNameOffset;
  };
  write_ixp_descriptor(kStage6IxpDescriptorSecondaryGlobalOffset,
                       kStage6IxpDescriptorSecondaryNameOffset);
  write_ixp_descriptor(kStage6IxpDescriptorTertiaryGlobalOffset,
                       kStage6IxpDescriptorTertiaryNameOffset);
  write_ixp_descriptor(kStage6IxpDescriptorQuaternaryGlobalOffset,
                       kStage6IxpDescriptorQuaternaryNameOffset);

  std::cout << "  [patch] installed Stage6 IXP descriptor fallback at 0x"
            << std::hex << kStage6IxpDescriptorPrimaryGlobalOffset << std::dec
            << " name=0x" << std::hex << kStage6IxpDescriptorPrimaryNameOffset
            << std::dec << '\n'
            << std::flush;
  return true;
}

bool InstallStage6DataModelPatchAnalyticsDescriptorFallbacks(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled(
          "MOCKTAIL_INSTALL_STAGE6_DATAMODEL_PATCH_ANALYTICS_DESCRIPTORS")) {
    return false;
  }

  const uintptr_t chain =
      libroblox_base +
      kStage6DataModelPatchAnalyticsDescriptorChainGlobalOffset;
  if (!IsReadableMemoryRange(chain, 0x110)) {
    std::cerr << "  [patch] Stage6 DataModel patch analytics descriptor "
              << "globals are unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(chain))) {
    std::cerr << "  [patch] Stage6 DataModel patch analytics descriptor global "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  const uintptr_t registry_head =
      libroblox_base +
      kStage6DataModelPatchAnalyticsDescriptorRegistryHeadGlobalOffset;
  const uintptr_t secondary_registry_head =
      libroblox_base +
      kStage6DataModelPatchAnalyticsDescriptorSecondaryRegistryHeadGlobalOffset;
  if (!IsReadableMemoryRange(registry_head, sizeof(uintptr_t)) ||
      !IsReadableMemoryRange(secondary_registry_head, sizeof(uintptr_t))) {
    std::cerr
        << "  [patch] Stage6 DataModel patch analytics descriptor registry "
        << "heads are unreadable\n"
        << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(registry_head)) ||
      !EnsureWritablePage(reinterpret_cast<void*>(secondary_registry_head))) {
    std::cerr
        << "  [patch] Stage6 DataModel patch analytics descriptor registry "
        << "mprotect failed: " << std::strerror(errno) << '\n'
        << std::flush;
    return false;
  }

  const uintptr_t previous_registry_head =
      *reinterpret_cast<uintptr_t*>(registry_head);
  const uintptr_t previous_secondary_registry_head =
      *reinterpret_cast<uintptr_t*>(secondary_registry_head);

  auto write_relative_pointer = [libroblox_base](uintptr_t slot_offset,
                                                 uintptr_t target_offset) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + slot_offset) =
        libroblox_base + target_offset;
  };
  auto write_pointer = [libroblox_base](uintptr_t slot_offset,
                                        uintptr_t value) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u64 = [libroblox_base](uintptr_t slot_offset, uint64_t value) {
    *reinterpret_cast<uint64_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u16 = [libroblox_base](uintptr_t slot_offset, uint16_t value) {
    *reinterpret_cast<uint16_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u8 = [libroblox_base](uintptr_t slot_offset, uint8_t value) {
    *reinterpret_cast<uint8_t*>(libroblox_base + slot_offset) = value;
  };

  write_u16(kStage6DataModelPatchAnalyticsDescriptorChainGlobalOffset, 0x0300);
  write_relative_pointer(0x73ceb08, 0x26d501);
  write_relative_pointer(0x73ceb10, 0x22bad54);
  write_pointer(0x73ceb18, previous_registry_head);
  write_relative_pointer(0x73ceb28, 0x22bad2f);
  write_relative_pointer(0x73ceb30, 0x73ceb10);
  write_relative_pointer(0x73ceb40, 0x22bad0a);
  write_relative_pointer(0x73ceb48, 0x73ceb28);
  write_u8(0x73ceb50, 0);
  write_relative_pointer(0x73ceb58, 0x2edeaf);
  write_u64(0x73ceb60, 0x20);
  write_relative_pointer(0x73ceb68, 0x22bace5);
  write_relative_pointer(0x73ceb70, 0x73ceb40);
  write_u8(0x73ceb78, 0);
  write_relative_pointer(0x73ceb80, 0x3a7436);
  write_u64(0x73ceb88, 0x2e);
  write_relative_pointer(0x73ceb90, 0x22bacc0);
  write_relative_pointer(0x73ceb98, 0x73ceb68);
  write_relative_pointer(0x73ceba0, 0x22f9343);
  write_pointer(0x73ceba8, previous_secondary_registry_head);
  write_relative_pointer(
      kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset,
      kStage6DataModelPatchAnalyticsDescriptorPrimaryNameOffset);
  write_relative_pointer(
      kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset + 0x08,
      kStage6DataModelPatchAnalyticsDescriptorDefaultNameOffset);
  write_relative_pointer(
      kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset + 0x10,
      kStage6DataModelPatchAnalyticsDescriptorPrimaryParentGlobalOffset);
  write_relative_pointer(
      0x73cebc8, kStage6DataModelPatchAnalyticsDescriptorSecondaryNameOffset);
  write_relative_pointer(
      0x73cebd0, kStage6DataModelPatchAnalyticsDescriptorDefaultNameOffset);
  write_relative_pointer(0x73cebd8, 0x73ceb38);

  WriteLibcxxString(
      reinterpret_cast<void*>(
          libroblox_base +
          kStage6DataModelPatchAnalyticsDescriptorSecondaryStringGlobalOffset),
      reinterpret_cast<const char*>(
          libroblox_base +
          kStage6DataModelPatchAnalyticsDescriptorSecondaryNameOffset));
  WriteLibcxxString(
      reinterpret_cast<void*>(
          libroblox_base +
          kStage6DataModelPatchAnalyticsDescriptorPrimaryStringGlobalOffset),
      reinterpret_cast<const char*>(
          libroblox_base +
          kStage6DataModelPatchAnalyticsDescriptorPrimaryNameOffset));

  *reinterpret_cast<uintptr_t*>(registry_head) = libroblox_base + 0x73ceb90;
  *reinterpret_cast<uintptr_t*>(secondary_registry_head) =
      libroblox_base + 0x73ceba0;

  std::cout
      << "  [patch] installed Stage6 DataModel patch analytics descriptor "
      << "fallback at 0x" << std::hex
      << kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset << std::dec
      << " name=0x" << std::hex
      << kStage6DataModelPatchAnalyticsDescriptorPrimaryNameOffset << std::dec
      << '\n'
      << std::flush;
  return true;
}

bool InstallStage6DataModelPatchTelemetryDescriptorFallbacks(
    uintptr_t libroblox_base) {
  if (libroblox_base == 0 ||
      IsDisabled(
          "MOCKTAIL_INSTALL_STAGE6_DATAMODEL_PATCH_TELEMETRY_DESCRIPTORS")) {
    return false;
  }

  const uintptr_t chain =
      libroblox_base +
      kStage6DataModelPatchTelemetryDescriptorChainGlobalOffset;
  if (!IsReadableMemoryRange(chain, 0x268)) {
    std::cerr << "  [patch] Stage6 DataModel patch telemetry descriptor "
              << "globals are unreadable\n"
              << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(chain))) {
    std::cerr << "  [patch] Stage6 DataModel patch telemetry descriptor global "
              << "mprotect failed: " << std::strerror(errno) << '\n'
              << std::flush;
    return false;
  }

  const uintptr_t registry_head =
      libroblox_base +
      kStage6DataModelPatchAnalyticsDescriptorRegistryHeadGlobalOffset;
  const uintptr_t secondary_registry_head =
      libroblox_base +
      kStage6DataModelPatchAnalyticsDescriptorSecondaryRegistryHeadGlobalOffset;
  if (!IsReadableMemoryRange(registry_head, sizeof(uintptr_t)) ||
      !IsReadableMemoryRange(secondary_registry_head, sizeof(uintptr_t))) {
    std::cerr
        << "  [patch] Stage6 DataModel patch telemetry descriptor registry "
        << "heads are unreadable\n"
        << std::flush;
    return false;
  }
  if (!EnsureWritablePage(reinterpret_cast<void*>(registry_head)) ||
      !EnsureWritablePage(reinterpret_cast<void*>(secondary_registry_head))) {
    std::cerr
        << "  [patch] Stage6 DataModel patch telemetry descriptor registry "
        << "mprotect failed: " << std::strerror(errno) << '\n'
        << std::flush;
    return false;
  }

  const uintptr_t previous_registry_head =
      *reinterpret_cast<uintptr_t*>(registry_head);
  const uintptr_t previous_secondary_registry_head =
      *reinterpret_cast<uintptr_t*>(secondary_registry_head);
  const uint8_t preserved_force_local_bits =
      *reinterpret_cast<uint8_t*>(libroblox_base +
                                  kStage6DataModelPatcherForceLocalFlagOffset) &
      0x01;

  auto write_relative_pointer = [libroblox_base](uintptr_t slot_offset,
                                                 uintptr_t target_offset) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + slot_offset) =
        libroblox_base + target_offset;
  };
  auto write_pointer = [libroblox_base](uintptr_t slot_offset,
                                        uintptr_t value) {
    *reinterpret_cast<uintptr_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u64 = [libroblox_base](uintptr_t slot_offset, uint64_t value) {
    *reinterpret_cast<uint64_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u16 = [libroblox_base](uintptr_t slot_offset, uint16_t value) {
    *reinterpret_cast<uint16_t*>(libroblox_base + slot_offset) = value;
  };
  auto write_u8 = [libroblox_base](uintptr_t slot_offset, uint8_t value) {
    *reinterpret_cast<uint8_t*>(libroblox_base + slot_offset) = value;
  };

  write_u16(kStage6DataModelPatchTelemetryDescriptorChainGlobalOffset, 0x0406);
  write_relative_pointer(0x73cf1e0, 0x44665e);
  write_relative_pointer(0x73cf1e8, 0x22ba845);
  write_pointer(0x73cf1f0, previous_registry_head);
  write_u64(kStage6DataModelPatchTelemetryDescriptorRootParentGlobalOffset, 0);
  write_relative_pointer(0x73cf200, 0x22ba820);
  write_relative_pointer(0x73cf208, 0x73cf1e8);
  write_relative_pointer(
      kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset,
      kStage6DataModelPatchTelemetryDescriptorRootNameOffset);
  write_relative_pointer(
      kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset + 0x08,
      kStage6DataModelPatchTelemetryDescriptorDefaultNameOffset);
  write_relative_pointer(
      kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset + 0x10,
      kStage6DataModelPatchTelemetryDescriptorRootParentGlobalOffset);
  write_u8(0x73cf228, 0);
  write_relative_pointer(0x73cf230, 0x2a1d24);
  write_u64(0x73cf238, 0x1e);
  write_relative_pointer(0x73cf240, 0x5fa7628);
  write_relative_pointer(0x73cf248, 0x73cf200);
  write_u8(0x73cf250, 0);
  write_relative_pointer(0x73cf258, 0x4e3525);
  write_u64(0x73cf260, 0x1c);
  write_relative_pointer(0x73cf268, 0x5fa764d);
  write_relative_pointer(0x73cf270, 0x73cf240);
  write_relative_pointer(0x73cf278, 0x5fa7672);
  write_pointer(0x73cf280, previous_secondary_registry_head);
  write_u8(kStage6DeferRbxmSignatureCheckToPostTtiFlagOffset, 0);
  write_relative_pointer(0x73cf290, 0x44666e);
  write_u64(0x73cf298, 0x20);
  write_relative_pointer(0x73cf2a0, 0x5fa76fc);
  write_relative_pointer(0x73cf2a8, 0x73cf268);
  write_u8(0x73cf2b0, 0);
  write_relative_pointer(0x73cf2b8, 0x517e2f);
  write_u64(0x73cf2c0, 0x1a);
  write_relative_pointer(0x73cf2c8, 0x22ba8d9);
  write_relative_pointer(0x73cf2d0, 0x73cf2a0);
  write_u8(kStage6DataModelPatcherForceLocalFlagOffset,
           preserved_force_local_bits);
  write_relative_pointer(0x73cf2e0, 0x37156d);
  write_u64(0x73cf2e8, 0x19);
  write_relative_pointer(0x73cf2f0, 0x5fa7721);
  write_relative_pointer(0x73cf2f8, 0x73cf2c8);
  write_u8(0x73cf300, 0);
  write_relative_pointer(0x73cf308, 0x2bad99);
  write_u64(0x73cf310, 0x1f);
  write_relative_pointer(0x73cf318, 0x5fa7746);
  write_relative_pointer(0x73cf320, 0x73cf2f0);
  write_u8(0x73cf328, 0);
  write_relative_pointer(0x73cf330, 0x26d5ca);
  write_u64(0x73cf338, 0x27);
  write_relative_pointer(0x73cf340, 0x5fa776b);
  write_relative_pointer(0x73cf348, 0x73cf318);
  write_u8(0x73cf350, 0);
  write_relative_pointer(0x73cf358, 0x33d1db);
  write_u64(0x73cf360, 0x21);
  write_relative_pointer(0x73cf368, 0x5fa7790);
  write_relative_pointer(0x73cf370, 0x73cf340);
  write_u8(0x73cf378, 0);
  write_relative_pointer(0x73cf380, 0x3dd795);
  write_u64(0x73cf388, 0x25);
  write_relative_pointer(0x73cf390, 0x5fa77b5);
  write_relative_pointer(0x73cf398, 0x73cf368);
  write_u8(0x73cf3a0, 0);
  write_relative_pointer(0x73cf3a8, 0x4c9526);
  write_u64(0x73cf3b0, 0x21);
  write_relative_pointer(0x73cf3b8, 0x5fa77da);
  write_relative_pointer(0x73cf3c0, 0x73cf390);
  write_u8(0x73cf3c8, 0);
  write_relative_pointer(0x73cf3d0, 0x479996);
  write_u64(0x73cf3d8, 0x23);
  write_relative_pointer(0x73cf3e0, 0x5fa77ff);
  write_relative_pointer(0x73cf3e8, 0x73cf3b8);
  write_u8(0x73cf3f0, 0);
  write_relative_pointer(0x73cf3f8, 0x3f8cbc);
  write_u64(0x73cf400, 0x22);
  write_relative_pointer(0x73cf408, 0x5fa7824);
  write_relative_pointer(0x73cf410, 0x73cf3e0);
  write_u8(0x73cf418, 0);
  write_relative_pointer(0x73cf420, 0x21e22f);
  write_relative_pointer(0x73cf428, 0x22ba820);
  write_relative_pointer(0x73cf430, 0x5fa7849);
  write_relative_pointer(0x73cf438, 0x73cf408);

  *reinterpret_cast<uintptr_t*>(registry_head) = libroblox_base + 0x73cf430;
  *reinterpret_cast<uintptr_t*>(secondary_registry_head) =
      libroblox_base + 0x73cf278;

  std::cout
      << "  [patch] installed Stage6 DataModel patch telemetry descriptor "
      << "fallback at 0x" << std::hex
      << kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset << std::dec
      << " name=0x" << std::hex
      << kStage6DataModelPatchTelemetryDescriptorRootNameOffset << std::dec
      << '\n'
      << std::flush;
  return true;
}

}  // namespace mocktail::legacy::internal
