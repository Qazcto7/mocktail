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

#ifndef MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_
#define MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_

#include <condition_variable>
#include <cstddef>
#include <mutex>

#include "mocktail/platform/platform_runtime.h"

namespace mocktail {
namespace window {

using PlatformEventObserver = void (*)(void* context,
                                       const platform::PlatformEvent& event);

// One process-scoped consumer receives events synchronously from the sole SDL
// polling loop. Clear and Deactivate remove the observer first, then wait for
// any callback that already copied it. The callback runs without this gate's
// mutex and must not synchronously clear its own registration.
class PlatformEventObserverGate final {
 public:
  bool Activate() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_) {
      return false;
    }
    observer_ = nullptr;
    context_ = nullptr;
    clearing_ = false;
    active_ = true;
    return true;
  }

  void Deactivate() {
    std::unique_lock<std::mutex> lock(mutex_);
    active_ = false;
    observer_ = nullptr;
    context_ = nullptr;
    condition_.wait(lock, [this] { return in_flight_ == 0; });
  }

  bool Register(PlatformEventObserver observer, void* context) {
    if (observer == nullptr || context == nullptr) {
      return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || clearing_ || observer_ != nullptr) {
      return false;
    }
    observer_ = observer;
    context_ = context;
    return true;
  }

  void Clear() {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return !clearing_; });
    clearing_ = true;
    observer_ = nullptr;
    context_ = nullptr;
    condition_.wait(lock, [this] { return in_flight_ == 0; });
    clearing_ = false;
    lock.unlock();
    condition_.notify_all();
  }

  bool HasObserver() {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_ && observer_ != nullptr;
  }

  void Notify(const platform::PlatformEvent& event) {
    PlatformEventObserver observer = nullptr;
    void* context = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!active_ || observer_ == nullptr) {
        return;
      }
      observer = observer_;
      context = context_;
      ++in_flight_;
    }
    observer(context, event);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      --in_flight_;
    }
    condition_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  PlatformEventObserver observer_ = nullptr;
  void* context_ = nullptr;
  std::size_t in_flight_ = 0;
  bool clearing_ = false;
  bool active_ = false;
};

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_PLATFORM_EVENT_OBSERVER_H_
