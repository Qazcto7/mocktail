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

#ifndef MOCKTAIL_COMPAT_HOST_ALLOCATOR_BRIDGE_H_
#define MOCKTAIL_COMPAT_HOST_ALLOCATOR_BRIDGE_H_

#include <cstddef>

namespace mocktail::compat {

// Explicit smoke-only ownership boundary for allocations returned to the
// guest. Unknown/native pointers are never inspected or freed.
void* HostAllocate(size_t size) noexcept;
void* HostAlignedAllocate(size_t size, size_t alignment) noexcept;
void* HostReallocate(void* pointer, size_t size) noexcept;
void HostFree(void* pointer) noexcept;
size_t HostUsableSize(void* pointer) noexcept;
void* HostAllocatorObjectAllocate(void* object, size_t size,
                                  size_t alignment) noexcept;

}  // namespace mocktail::compat

#endif  // MOCKTAIL_COMPAT_HOST_ALLOCATOR_BRIDGE_H_
