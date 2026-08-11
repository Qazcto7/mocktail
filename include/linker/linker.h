// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// linker/linker.h — ELF Bionic-compatible shared library loader.
//
// Provides a minimal interface for loading Android ELF shared libraries
// (.so files compiled for Bionic libc / Android ABI) into a Linux process
// address space, resolving dependencies and exporting a symbol table.
//
// Design notes:
//   - Uses dlopen(3) under the hood for system libraries.
//   - For Bionic-ABI libraries (libroblox.so), manual ELF parsing and
//     mmap(2)-based loading is required; this header exposes that interface.
//   - All paths follow POSIX conventions.

#ifndef MOCKTAIL_LINKER_LINKER_H_
#define MOCKTAIL_LINKER_LINKER_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace linker {

// Opaque handle returned by LoadLibrary. Callers must not interpret the
// pointer value; it is only valid as an argument to ResolveSymbol or
// UnloadLibrary.
using LibraryHandle = void*;
using SymbolMap = std::unordered_map<std::string, void*>;
using AndroidLibraryLoadObserver = bool (*)(void* context,
                                            std::string_view logical_name,
                                            std::uintptr_t image_base);

struct ProgramHeaderValidation {
  bool valid = false;
  std::string error;

  explicit operator bool() const noexcept { return valid; }
};

// AddSyntheticLibrary — registers one Android SONAME and only the exports
// owned by that library. Dependencies of subsequently loaded Android ELF
// files resolve these symbols through mcpelauncher-linker.
LibraryHandle AddSyntheticLibrary(const std::string& soname,
                                  const SymbolMap& exports);

// RegisterSyntheticSymbol — stages or adds one export to a specific Android
// SONAME. If the synthetic library is already loaded, its symbol table is
// updated in place.
void RegisterSyntheticSymbol(const std::string& soname,
                             const std::string& name, void* address);

// Registers Android Bionic thread-local and synchronization ABIs only
// for synthetic libc.so. Host code keeps its glibc implementations.
void RegisterBionicPthreadKeyRuntimeForLibc();

// Registers Android's DSO-aware __register_atfork entrypoint only for
// synthetic libc.so. The host pthread bridge preserves callback order but
// cannot unregister callbacks when a guest DSO unloads.
void RegisterBionicAtForkRuntimeForLibc();

// Registers Android LP64 positioned I/O and seek entrypoints only for
// synthetic libc.so. The bridge relies on the x86-64 host's 64-bit
// off_t contract and never exposes host large-file feature-macro aliases.
void RegisterBionicLargeFileRuntimeForLibc();

// Registers host-independent implementations of Android libc exports that
// are not uniformly supplied by glibc and musl. Every symbol remains owned by
// synthetic libc.so and preserves the Android x86-64 ABI.
void RegisterBionicHostLibcRuntimeForLibc();

// Registers Bionic sysconf name translation only for synthetic libc.so.
// Bionic and glibc use different integer values for sysconf names.
void RegisterBionicSysconfRuntimeForLibc();

// Registers the Android LP64 sigaction layout adapter only for libc.so.
void RegisterBionicSignalRuntimeForLibc();

// Registers the LP64 Bionic FILE/__sF ABI and host stdio translation only for
// synthetic libc.so.
void RegisterBionicStdioRuntimeForLibc();

// Restores mcpelauncher-linker's own libdl exports after legacy host-symbol
// discovery. Android dlopen/dlsym must never escape into glibc.
void RegisterBionicDynamicLoaderForLibdl();

// GetSyntheticLibrarySymbols — returns a snapshot of one SONAME's exports.
// The copy is safe to inspect while other libraries are being registered.
SymbolMap GetSyntheticLibrarySymbols(const std::string& soname);

// UpdateAndroidLibraryPath — configures the Bionic linker's dependency search
// path. Multiple directories use the same colon-separated syntax as
// LD_LIBRARY_PATH.
void UpdateAndroidLibraryPath(const std::string& search_path);

// Installs the single process owner that validates or adapts a real Android
// image immediately after relocation and registration. Returning false from
// the observer rejects and unloads that image before startup can call it.
bool SetAndroidLibraryLoadObserver(AndroidLibraryLoadObserver observer,
                                   void* context);
void ClearAndroidLibraryLoadObserver(void* context);

// OpenAndroidLibrary — loads a real Android ELF and registers its handle under
// logical_name. The containing directory is added to the Bionic dependency
// search path before loading.
LibraryHandle OpenAndroidLibrary(const std::string& real_path,
                                 const std::string& logical_name);

// Legacy compatibility bridge. New code should use AddSyntheticLibrary or
// OpenAndroidLibrary so real files and synthetic SONAMEs cannot be confused.
LibraryHandle LoadLibrary(const std::string& real_path,
                          const std::string& host_alias);

// ResolveSymbol — looks up an exported symbol in a loaded library.
void* ResolveSymbol(LibraryHandle handle, const std::string& symbol_name);

// Crashpad execution is intentionally outside Mocktail's supported JNI
// surface. These exports are never returned to the host composition even when
// a Roblox payload contains them.
bool IsBlockedRobloxCrashReportNativeSymbol(
    std::string_view symbol_name) noexcept;

// UnloadLibrary — releases resources associated with a loaded library.
void UnloadLibrary(LibraryHandle handle);

// Legacy compatibility bridge used by the current monolithic startup path.
// New code should use RegisterSyntheticSymbol and assign every export to its
// owning SONAME.
void RegisterSymbol(const std::string& name, void* addr);

// Returns the legacy accumulated symbol table. It remains available until the
// existing startup path is migrated to per-SONAME maps.
const SymbolMap& GetBionicSymbols();

// Returns mcpelauncher-linker's Bionic dl_iterate_phdr entrypoint. Android
// unwinders must not receive glibc's host implementation/layout.
void* BionicDlIteratePhdrAddress();

// Confirms that the Bionic program-header iterator can see a manually loaded
// Android ELF, including the unwind metadata needed for C++ exceptions.
ProgramHeaderValidation ValidateBionicProgramHeaders(LibraryHandle handle);

// Returns the mapped ELF base for a loaded Android library alias. The lookup
// is synchronized with library registration and returns zero for an unknown
// alias or a host-dlopen library without Bionic image metadata.
std::uintptr_t FindLoadedAndroidLibraryBase(const std::string& logical_name);

// SymbolTable — global registry of alias → handle mappings.
const std::unordered_map<std::string, LibraryHandle>& GetSymbolTable();

}  // namespace linker

#endif  // MOCKTAIL_LINKER_LINKER_H_
