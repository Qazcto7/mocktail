#ifndef MOCKTAIL_LEGACY_RBXM_DIAGNOSTICS_H_
#define MOCKTAIL_LEGACY_RBXM_DIAGNOSTICS_H_

#include <cstddef>
#include <cstdint>

namespace mocktail::legacy::internal {

void ReadRbxmInstanceNameSlotPreview(std::uintptr_t object, char* out,
                                     std::size_t out_size);
void ReadRbxmInstanceStringFieldCandidatesPreview(std::uintptr_t object,
                                                  char* out,
                                                  std::size_t out_size);
bool RepairStage6RbxmInstanceNameSlotFromValue(std::uintptr_t object,
                                               std::uintptr_t value_variant,
                                               const char* reason);
void ReadRbxmValueContextStringVectorPreview(std::uintptr_t value_context,
                                             char* out, std::size_t out_size);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_RBXM_DIAGNOSTICS_H_
