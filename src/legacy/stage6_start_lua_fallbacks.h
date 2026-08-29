#ifndef MOCKTAIL_LEGACY_STAGE6_START_LUA_FALLBACKS_H_
#define MOCKTAIL_LEGACY_STAGE6_START_LUA_FALLBACKS_H_

#include <cstdint>

namespace mocktail::legacy::internal {

extern "C" void mocktail_stage6_start_lua_noop_continuation(void* self,
                                                            void* arg1,
                                                            void* arg2);

std::uintptr_t InstallStage6StartLuaTargetCallbackObject(std::uintptr_t target,
                                                         std::uintptr_t context,
                                                         const char* reason);
std::uintptr_t PrepareStage6StartLuaResult20SplitCallbackContext(
    std::uintptr_t callback, std::uintptr_t source_pair);
std::uintptr_t PrepareStage6StartLuaSyntheticInstanceSource(
    std::uintptr_t source_value, const char* reason);
std::uintptr_t InstallStage6StartLuaFallbackCallbackTarget(std::uintptr_t owner,
                                                           const char* reason);
std::uintptr_t InstallStage6StartLuaFallbackState(
    std::uintptr_t owner, std::uintptr_t configured_anchor, const char* reason);
bool SeedStage6StartLuaGatePayload(std::uintptr_t payload, const char* reason);
bool SeedStage6StartLuaDeepStateHeader(std::uintptr_t state,
                                       const char* reason);
bool SeedStage6StartLuaPrimaryStateFromOwner(std::uintptr_t owner,
                                             const char* reason);
void LogStage6StartLuaTargetCandidates(std::uintptr_t object);
bool SeedStage6StartLuaTargetTableFallback(std::uintptr_t object,
                                           std::uint32_t index);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_START_LUA_FALLBACKS_H_
