// Copyright 2026 Sober Test Project Authors
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

// libc_shim/libc_shim.h — Bionic libc → Glibc call translation layer.
//
// Intercepts calls made by Bionic-compiled code (libroblox.so) to
// Bionic-specific libc functions and forwards them to their Glibc equivalents
// on the host Linux system.
//
// Key responsibilities:
//   - pthread_mutex_t size/layout differences between Bionic and Glibc.
//   - Virtual filesystem path mapping (APK sandbox → Flatpak paths).
//   - Bionic-only syscall wrappers missing in Glibc.

#ifndef SOBER_TEST_LIBC_SHIM_LIBC_SHIM_H_
#define SOBER_TEST_LIBC_SHIM_LIBC_SHIM_H_

#include <cstdio>
#include <dirent.h>
#include <string>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>

namespace libc_shim {

using GuestAllocator = void* (*)(size_t);

enum class HostCaBundleStatus {
  kReady,
  kInvalidOverride,
  kUnavailable,
};

struct HostCaBundleResolution {
  HostCaBundleStatus status = HostCaBundleStatus::kUnavailable;
  std::string host_path;
  bool from_override = false;

  bool ok() const { return status == HostCaBundleStatus::kReady; }
};

// Selects the allocator used by libc APIs whose POSIX contract returns an
// owned buffer. This keeps allocations on the same side of the host/guest ABI
// boundary as the caller that will later free them.
void ConfigureGuestAllocator(GuestAllocator allocator) noexcept;

// Installs all shim hooks. Must be called before the target .so is loaded.
//
// After this call, dlopen(3) symbol resolution for known Bionic symbols will
// be intercepted and redirected to the shim implementations.
void Install();

// Resolves the host TLS trust bundle without weakening certificate
// verification. MOCKTAIL_CA_BUNDLE, when present, is authoritative and must
// name a readable, non-empty, absolute regular file; an invalid override never
// falls back to a system path.
HostCaBundleResolution ResolveHostCaBundle();

// Resolves and registers exact Android CA-file aliases. The aliases are more
// specific than the application data prefix and therefore retain the existing
// longest-prefix path semantics for every other application path.
HostCaBundleResolution ConfigureHostCaBundlePathMappings();

const char* HostCaBundleStatusName(HostCaBundleStatus status);

// Maps an Android-style virtual path to its Flatpak sandbox equivalent.
//
// Example:
//   "/data/user/0/com.roblox.client/files/logs" →
//   "/home/user/.var/app/org.vinegarhq.Sober/data/sober/logs"
//
// Args:
//   android_path: Absolute path as seen by the Bionic library.
//
// Returns:
//   Translated host path. Returns android_path unchanged if no mapping
//   is registered for it.
std::string TranslatePath(const std::string& android_path);

// Registers a path prefix mapping used by TranslatePath.
//
// Args:
//   android_prefix: Android path prefix to intercept.
//   host_prefix:    Replacement prefix on the host filesystem.
void RegisterPathMapping(const std::string& android_prefix,
                         const std::string& host_prefix);

// Removes all registered path mappings. Primarily for use in tests.
void ClearPathMappings();

}  // namespace libc_shim

extern "C" {
int mocktail_open(const char* path, int flags, ...);
int mocktail___open_2(const char* path, int flags);
FILE* mocktail_fopen(const char* path, const char* mode);
int mocktail_access(const char* path, int mode);
int mocktail_stat(const char* path, struct stat* statbuf);
int mocktail_lstat(const char* path, struct stat* statbuf);
int mocktail_statvfs(const char* path, struct statvfs* statbuf);
int mocktail_statfs(const char* path, struct statfs* statbuf);
int mocktail_mkdir(const char* path, mode_t mode);
DIR* mocktail_opendir(const char* path);
int mocktail_rename(const char* old_path, const char* new_path);
int mocktail_unlink(const char* path);
int mocktail_rmdir(const char* path);
char* mocktail_realpath(const char* path, char* resolved_path);
ssize_t mocktail_readlink(const char* path, char* buf, size_t bufsiz);
ssize_t mocktail___readlink_chk(const char* path, char* buf, size_t len,
                                size_t buf_len);
}

#endif  // SOBER_TEST_LIBC_SHIM_LIBC_SHIM_H_
