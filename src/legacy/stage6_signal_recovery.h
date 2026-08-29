#ifndef MOCKTAIL_LEGACY_STAGE6_SIGNAL_RECOVERY_H_
#define MOCKTAIL_LEGACY_STAGE6_SIGNAL_RECOVERY_H_

#include <signal.h>
#include <ucontext.h>

#include <cstdint>

namespace mocktail::legacy::internal {

bool TryHandleStage5LowAddressAtomic(ucontext_t* ucontext,
                                     unsigned char* instruction);
bool TryHandleStage5MisalignedAtomic(ucontext_t* ucontext,
                                     unsigned char* instruction);
bool TryHandleStage6StartLuaTraceTrap(int signo, std::uintptr_t libroblox_base,
                                      std::uintptr_t libroblox_offset,
                                      ucontext_t* ucontext);
bool TryHandleStage6GlQueueTraceTrap(int signo, std::uintptr_t libroblox_base,
                                     std::uintptr_t libroblox_offset,
                                     ucontext_t* ucontext);
bool TryHandleStage6FmodTraceTrap(int signo, std::uintptr_t libroblox_base,
                                  std::uintptr_t libroblox_offset,
                                  ucontext_t* ucontext);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_SIGNAL_RECOVERY_H_
