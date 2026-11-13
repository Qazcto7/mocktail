#include "compat/host_allocator_bridge.h"

#include "mocktail/mocktail_rust.h"

namespace mocktail::compat {

void* HostAlignedAllocate(size_t size, size_t alignment) noexcept {
  return mocktail_rust_host_aligned_allocate(size, alignment);
}

void* HostAllocate(size_t size) noexcept {
  return mocktail_rust_host_allocate(size);
}

void* HostReallocate(void* pointer, size_t size) noexcept {
  return mocktail_rust_host_reallocate(pointer, size);
}

void HostFree(void* pointer) noexcept {
  mocktail_rust_host_free(pointer);
}

size_t HostUsableSize(void* pointer) noexcept {
  return mocktail_rust_host_usable_size(pointer);
}

void* HostAllocatorObjectAllocate(void*, size_t size,
                                  size_t alignment) noexcept {
  return HostAlignedAllocate(size, alignment);
}

}  // namespace mocktail::compat
