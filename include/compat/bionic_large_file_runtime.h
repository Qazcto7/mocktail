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

#ifndef MOCKTAIL_COMPAT_BIONIC_LARGE_FILE_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_LARGE_FILE_RUNTIME_H_

#include <sys/types.h>

#include <cstddef>
#include <cstdint>

namespace mocktail::compat {

// Android x86-64 defines off64_t as a signed 64-bit offset. A fixed-width
// public type keeps the guest ABI independent of host feature-test macros.
using BionicOff64 = int64_t;

ssize_t BionicPread64(int fd, void* buffer, size_t count,
                      BionicOff64 offset) noexcept;
ssize_t BionicPwrite64(int fd, const void* buffer, size_t count,
                       BionicOff64 offset) noexcept;
BionicOff64 BionicLseek64(int fd, BionicOff64 offset, int whence) noexcept;

}  // namespace mocktail::compat

extern "C" {

ssize_t mocktail_bionic_pread64(int fd, void* buffer, size_t count,
                                mocktail::compat::BionicOff64 offset);
ssize_t mocktail_bionic_pwrite64(int fd, const void* buffer, size_t count,
                                 mocktail::compat::BionicOff64 offset);
mocktail::compat::BionicOff64
mocktail_bionic_lseek64(int fd, mocktail::compat::BionicOff64 offset,
                        int whence);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_LARGE_FILE_RUNTIME_H_
