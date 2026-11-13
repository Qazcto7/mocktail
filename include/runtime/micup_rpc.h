#ifndef MOCKTAIL_RUNTIME_MICUP_RPC_H_
#define MOCKTAIL_RUNTIME_MICUP_RPC_H_

#include <memory>
#include <string>

#include "runtime/roblox_experience_presence.h"
#include "runtime/runtime_config.h"

namespace mocktail {
namespace runtime {

// Maintains an authenticated Micup Gateway WebSocket Rich Presence session.
// All protocol, WebSocket/TLS, heartbeat, and rate-limit logic lives in
// Rust (`mocktail-core`); C++ forwards Roblox lifecycle phases and shares the
// common Roblox place metadata cache with Discord RPC.
class MicupRpcSession final {
 public:
  explicit MicupRpcSession(MicupRpcConfig config);
  ~MicupRpcSession();

  MicupRpcSession(const MicupRpcSession&) = delete;
  MicupRpcSession& operator=(const MicupRpcSession&) = delete;

  bool Start(std::string* detail = nullptr);
  void Stop();
  RobloxExperiencePresenceObserver observer();

 private:
  class Impl;
  static void Notify(void* context, RobloxExperiencePresencePhase phase,
                     const RobloxExperienceLaunchRequest* request);

  std::unique_ptr<Impl> impl_;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_MICUP_RPC_H_
