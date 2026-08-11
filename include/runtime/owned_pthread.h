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

#ifndef MOCKTAIL_RUNTIME_OWNED_PTHREAD_H_
#define MOCKTAIL_RUNTIME_OWNED_PTHREAD_H_

#include <pthread.h>

#include <cstddef>

namespace mocktail {
namespace runtime {

using PthreadEntryPoint = void* (*)(void* context);
using PthreadWaitPump = void (*)(void* context);

enum class OwnedPthreadWaitStatus {
  kJoined,
  kTimedOut,
  kPlatformError,
};

struct OwnedPthreadWaitResult {
  OwnedPthreadWaitStatus status = OwnedPthreadWaitStatus::kPlatformError;
  int platform_error = 0;

  bool joined() const { return status == OwnedPthreadWaitStatus::kJoined; }
};

struct OwnedPthreadCancelResult {
  int cancel_error = 0;
  OwnedPthreadWaitResult wait;
};

// Owns a joinable Linux pthread. There is intentionally no detach operation:
// context and every dependency reachable by a worker must outlive a physical
// join. Destroying a still-joinable instance terminates the process without
// unwinding, preventing a live worker from observing released stack or RAII
// state.
class OwnedPthread final {
 public:
  OwnedPthread() = default;
  ~OwnedPthread();

  OwnedPthread(const OwnedPthread&) = delete;
  OwnedPthread& operator=(const OwnedPthread&) = delete;

  int Start(PthreadEntryPoint entry_point, void* context,
            std::size_t stack_size);
  OwnedPthreadWaitResult WaitFor(int timeout_ms, int poll_interval_ms,
                                 PthreadWaitPump pump = nullptr,
                                 void* pump_context = nullptr);
  OwnedPthreadCancelResult CancelAndJoinFor(int timeout_ms,
                                            int poll_interval_ms,
                                            PthreadWaitPump pump = nullptr,
                                            void* pump_context = nullptr);
  int Signal(int signal_number) const;

  bool joinable() const { return joinable_; }

 private:
  pthread_t thread_{};
  bool joinable_ = false;
};

const char* OwnedPthreadWaitStatusName(OwnedPthreadWaitStatus status);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_OWNED_PTHREAD_H_
