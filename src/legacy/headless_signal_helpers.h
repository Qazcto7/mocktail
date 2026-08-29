#ifndef MOCKTAIL_LEGACY_HEADLESS_SIGNAL_HELPERS_H_
#define MOCKTAIL_LEGACY_HEADLESS_SIGNAL_HELPERS_H_

#include <signal.h>
#include <sys/types.h>
#include <ucontext.h>

#include <cstdint>

namespace mocktail::legacy::internal {

[[noreturn]] void ExitCurrentThreadImmediately();
bool TryRecoverRepeatedStage6GuardLoop();
bool TryReturnFromRepeatedStage6StringFieldLoop(ucontext_t* ucontext,
                                                std::uintptr_t libroblox_base,
                                                std::uintptr_t libroblox_offset,
                                                std::uintptr_t value);
bool ShouldLogStage6Repeated(volatile sig_atomic_t* counter);
bool IsLikelyUserPointer(std::uintptr_t value);
std::uintptr_t AllocateStage6StartAppNullAllocatorArena(
    std::uintptr_t requested_size, bool* arena_wrapped,
    std::uintptr_t* total_size_out);
bool TryReturnFromStage6StartAppNullAllocatorFree(
    ucontext_t* ucontext, std::uintptr_t libroblox_offset);
bool TryHandleStage6StartAppZeroStrideDivisor(int signo,
                                              std::uintptr_t libroblox_base,
                                              std::uintptr_t libroblox_offset,
                                              ucontext_t* ucontext,
                                              const unsigned char* instruction,
                                              bool instruction_readable);
bool TryHandleStage6StartAppNullStateObjectRead(
    int signo, siginfo_t* info, std::uintptr_t libroblox_base,
    std::uintptr_t libroblox_offset, ucontext_t* ucontext,
    const unsigned char* instruction, bool instruction_readable);
bool TryHandleStage6StartLuaObserverListInvalidCursor(
    int signo, siginfo_t* info, std::uintptr_t libroblox_base,
    std::uintptr_t libroblox_offset, ucontext_t* ucontext,
    const unsigned char* instruction, bool instruction_readable);
bool TryReturnFromStage6ErroneousFunctionPointerCall(int signo, siginfo_t* info,
                                                     ucontext_t* ucontext);
bool TryReturnFromStage6UpdateSurfaceNonCodeCallback(int signo, siginfo_t* info,
                                                     ucontext_t* ucontext);
void LogStage6RecoverySignal(const char* label, ucontext_t* ucontext,
                             siginfo_t* info, int signo,
                             std::uintptr_t libroblox_offset);
bool TryReturnFromStage6ActivityLifecycleNullObserver(
    ucontext_t* ucontext, std::uintptr_t libroblox_offset);
void DumpThreadPcSignalHandler(int signo, siginfo_t* info, void* context);
void ResetStartAppManagerScratch();
void SeedStage6GlUnsupportedMessageSlot();
void* GetThreadScratchBuffer(pid_t tid);
void InitialiseStage6GlScratch(unsigned char* region);

extern const std::uintptr_t kFallbackObject[4];

void PrintBacktraceNoSig(const char* prefix);
bool TryRecoverStage6StartLuaTargetTableDynamicCastTypeInfo(
    ucontext_t* ucontext, std::uintptr_t libroblox_offset);
bool ShouldPatchStage6StartGameOwnerGameState();
std::uintptr_t PrepareStage6StartGameMapEntryScratch(const char* reason);
std::uintptr_t PrepareStage6StartGameEmptyItemScratch(const char* reason);
bool UnwindStage6StartLuaSetupFrame(ucontext_t* ucontext);
bool TryReturnFromDecodedRbpFrame(ucontext_t* ucontext,
                                  const unsigned char* instruction,
                                  std::uintptr_t code_base,
                                  std::uintptr_t return_value);
void PrintContextBacktrace(ucontext_t* ucontext, const char* prefix);
void PrintAddressMapForRip(std::uintptr_t address);
void LogStage6StartAppNonCodeTargetDetail(ucontext_t* ucontext);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_HEADLESS_SIGNAL_HELPERS_H_
