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

#ifndef MOCKTAIL_RUNTIME_EXTERNAL_LAUNCH_BROKER_H_
#define MOCKTAIL_RUNTIME_EXTERNAL_LAUNCH_BROKER_H_

#include <cstddef>
#include <filesystem>
#include <memory>

#include "mocktail/status.h"
#include "runtime/roblox_experience_launch_bridge.h"

namespace mocktail {
namespace runtime {

inline constexpr std::size_t kMaximumPendingExternalLaunches = 8;

struct ExternalLaunchBrokerOptions {
  // Empty selects the current user's protected runtime endpoint. Tests and
  // isolated launchers may provide an explicit socket under a private
  // directory owned by the current user.
  std::filesystem::path socket_path;
  std::size_t maximum_pending_launches = kMaximumPendingExternalLaunches;
  // The owner crosses configuration/bootstrap and a possible cgroup
  // re-exec before it can safely ACK. A concurrent browser click waits through
  // that bounded startup window instead of racing a not-yet-created socket.
  int forwarding_timeout_ms = 30000;
};

using DispatchExternalLaunchFn =
    Status (*)(void* context, const RobloxExperienceLaunchRequest& request);

struct ExternalLaunchSink {
  void* context = nullptr;
  DispatchExternalLaunchFn dispatch = nullptr;

  bool valid() const { return dispatch != nullptr; }
};

// Resolves the per-user, per-installation endpoint. Owner resolution may
// create only the private fallback directory; it never removes a stale
// socket. Socket cleanup belongs exclusively to StartOwnerAfterLockAcquired
// after the caller owns the matching Mocktail single-instance lock.
Status ResolveExternalLaunchSocketPath(bool owner,
                                       std::filesystem::path* socket_path);

// Owns a bounded process-local launch queue and its same-user AF_UNIX endpoint.
// Wire requests contain only already-normalized ExperienceProtocol JSON; the
// raw browser URI and its gameinfo ticket never cross this boundary.
class ExternalLaunchBroker final {
 public:
  ~ExternalLaunchBroker();

  ExternalLaunchBroker(const ExternalLaunchBroker&) = delete;
  ExternalLaunchBroker& operator=(const ExternalLaunchBroker&) = delete;
  ExternalLaunchBroker(ExternalLaunchBroker&&) = delete;
  ExternalLaunchBroker& operator=(ExternalLaunchBroker&&) = delete;

  // The caller must hold the single-instance lock. Only this operation may
  // remove a stale socket left by a crashed owner. An optional initial request
  // is normalized and queued before the listener worker can accept later
  // browser clicks, preserving click order without a startup race.
  static Status StartOwnerAfterLockAcquired(
      ExternalLaunchBrokerOptions options,
      std::shared_ptr<ExternalLaunchBroker>* broker,
      const RobloxExperienceLaunchRequest* initial_request = nullptr);

  // Forwards one normalized request and waits for an explicit owner ACK. The
  // operation never starts a second runtime and never logs request contents.
  static Status ForwardToOwner(const ExternalLaunchBrokerOptions& options,
                               const RobloxExperienceLaunchRequest& request);

  Status QueueInitialRequest(RobloxExperienceLaunchRequest request);

  // Dispatches at most maximum_requests in FIFO order. A failed dispatch is
  // returned to the front of the queue, so temporary downstream backpressure
  // never drops a browser launch.
  Status Drain(const ExternalLaunchSink& sink, std::size_t maximum_requests);

  Status Shutdown();
  std::size_t pending_launch_count() const;
  const std::filesystem::path& socket_path() const;

 private:
  class Impl;
  explicit ExternalLaunchBroker(std::unique_ptr<Impl> impl);

  std::unique_ptr<Impl> impl_;
};

// Process-global attachment used by the composition root and the dynamic
// ExperienceProtocol runtime. shared_ptr acquisition keeps the broker alive
// while an external request is being drained.
Status InstallActiveExternalLaunchBroker(
    const std::shared_ptr<ExternalLaunchBroker>& broker);
void ClearActiveExternalLaunchBroker(const ExternalLaunchBroker* broker);
std::shared_ptr<ExternalLaunchBroker> GetActiveExternalLaunchBroker();
Status DrainActiveExternalLaunchRequests(const ExternalLaunchSink& sink,
                                         std::size_t maximum_requests);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_EXTERNAL_LAUNCH_BROKER_H_
