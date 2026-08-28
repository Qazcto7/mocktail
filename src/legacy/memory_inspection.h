#ifndef MOCKTAIL_LEGACY_MEMORY_INSPECTION_H_
#define MOCKTAIL_LEGACY_MEMORY_INSPECTION_H_

#include <cstddef>
#include <cstdint>

namespace mocktail::legacy::internal {

bool IsReadableMemoryRange(std::uintptr_t address, std::size_t size);
bool IsExecutableMemoryRange(std::uintptr_t address, std::size_t size);
bool EnsureWritablePage(void* address);
std::uintptr_t ReadPointerIfReadable(std::uintptr_t address);
std::uint32_t ReadU32IfReadable(std::uintptr_t address);
unsigned long long ReadVectorElementCountIfReadable(
    std::uintptr_t vector_address, std::uintptr_t element_size);
void ReadLibcxxStringPreview(std::uintptr_t address, char* out,
                             std::size_t out_size);
bool ReadLibcxxStringView(std::uintptr_t address, const char** chars_out,
                          std::size_t* length_out);
void ReadMemoryHexPreview(std::uintptr_t address, char* out,
                          std::size_t out_size);
void ReadRawStringPreview(std::uintptr_t address, std::size_t length, char* out,
                          std::size_t out_size);
void ReadCStringPreview(std::uintptr_t address, char* out,
                        std::size_t out_size);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_MEMORY_INSPECTION_H_
