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

#ifndef MOCKTAIL_COMPAT_BIONIC_PTHREAD_CREATE_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_PTHREAD_CREATE_RUNTIME_H_

#include <pthread.h>

#include <cstddef>

namespace mocktail::compat {

using NativeThreadInitializer = void (*)();

// Pinned Bionic LP64 pthread_internal.h keeps total per-thread reservation
// near 1 MiB by subtracting its 32 KiB alternate signal stack from the normal
// thread stack. Host defaults are not ABI substitutes: musl's default is only
// 128 KiB on the supported Void runtime.
inline constexpr size_t kBionicLp64DefaultThreadStackSize =
    (1U * 1024U * 1024U) - (32U * 1024U);
static_assert(kBionicLp64DefaultThreadStackSize == 1015808U);

// Used only after a Bionic-sized stack is rejected by the host at thread
// creation time. The retry takes the largest of this floor, the requested
// guest size, and the host default. That retains enough stack on musl without
// shrinking glibc's default.
inline constexpr size_t kBionicLp64FallbackThreadStackSize = 2U * 1024U * 1024U;

// Installs the payload-owned per-thread initializer used by subsequently
// created guest threads. Passing nullptr restores ordinary host behavior.
void ConfigureBionicPthreadThreadInitializer(
    NativeThreadInitializer initializer) noexcept;

}  // namespace mocktail::compat

// Creates a host thread after rebuilding the supported POSIX attributes.
// Rebuilding avoids passing ABI-private pthread_attr_t state from the Android
// payload directly into glibc.
extern "C" int mocktail_bionic_pthread_create(pthread_t* thread,
                                               const pthread_attr_t* attr,
                                               void* (*start_routine)(void*),
                                               void* argument);

#endif  // MOCKTAIL_COMPAT_BIONIC_PTHREAD_CREATE_RUNTIME_H_
