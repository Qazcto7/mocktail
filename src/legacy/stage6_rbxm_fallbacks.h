#ifndef MOCKTAIL_LEGACY_STAGE6_RBXM_FALLBACKS_H_
#define MOCKTAIL_LEGACY_STAGE6_RBXM_FALLBACKS_H_

#include <cstddef>
#include <cstdint>

namespace mocktail::legacy::internal {

void ReadRbxmFileManagerCacheRegistryPreview(std::uintptr_t libroblox_base,
                                             char* out, std::size_t out_size);
void ReadRbxmFileManagerFeatureRegistryPreview(std::uintptr_t libroblox_base,
                                               char* out, std::size_t out_size);
void ReadRbxmCoreClassRegistryPreview(std::uintptr_t libroblox_base, char* out,
                                      std::size_t out_size);
void ReadRbxmDescriptorNameCandidate(std::uintptr_t descriptor, char* out,
                                     std::size_t out_size);
void ReadRbxmDescriptorRegistryPreview(std::uintptr_t libroblox_base, char* out,
                                       std::size_t out_size);

bool IsLikelyCallableRbxmPropertyDescriptor(std::uintptr_t descriptor);
bool RepairStage6RbxmNameDescriptorForRbxmApply(std::uintptr_t descriptor,
                                                const char* reason);
void LogRbxmPropertyDescriptorCandidateReject(const char* expected_name,
                                              const char* reason,
                                              std::uintptr_t candidate);
void CacheStage6RbxmNameDescriptor(std::uintptr_t descriptor);
bool IsCachedStage6RbxmNameDescriptor(std::uintptr_t descriptor);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_RBXM_FALLBACKS_H_
