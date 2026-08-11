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

#include "compat/bionic_pthread_create_runtime.h"

#include <errno.h>

#include <algorithm>
#include <atomic>
#include <new>

namespace mocktail::compat {
namespace {

struct ThreadStartContext {
  void* (*start_routine)(void*) = nullptr;
  void* argument = nullptr;
  NativeThreadInitializer initializer = nullptr;
};

std::atomic<NativeThreadInitializer> g_thread_initializer{nullptr};

int CopySupportedThreadAttributes(const pthread_attr_t& source,
                                  pthread_attr_t* destination) noexcept {
  int detach_state = PTHREAD_CREATE_JOINABLE;
  int result = pthread_attr_getdetachstate(&source, &detach_state);
  if (result != 0) {
    return result;
  }
  result = pthread_attr_setdetachstate(destination, detach_state);
  if (result != 0) {
    return result;
  }

  size_t guard_size = 0;
  result = pthread_attr_getguardsize(&source, &guard_size);
  if (result != 0) {
    return result;
  }
  result = pthread_attr_setguardsize(destination, guard_size);
  if (result != 0) {
    return result;
  }

  // The compatibility surface exposes pthread_attr_setstacksize, but not
  // pthread_attr_setstack. Copying pthread_attr_getstack's address is unsafe:
  // glibc represents an automatically allocated stack with a synthetic
  // address derived from its size.
  size_t stack_size = 0;
  result = pthread_attr_getstacksize(&source, &stack_size);
  if (result != 0) {
    return result;
  }
  result = pthread_attr_setstacksize(destination, stack_size);
  if (result != 0) {
    return result;
  }

  int inherit_scheduler = PTHREAD_INHERIT_SCHED;
  result = pthread_attr_getinheritsched(&source, &inherit_scheduler);
  if (result != 0) {
    return result;
  }
  if (inherit_scheduler == PTHREAD_EXPLICIT_SCHED) {
    int scheduler_policy = 0;
    sched_param scheduler_parameters{};
    result = pthread_attr_getschedpolicy(&source, &scheduler_policy);
    if (result == 0) {
      result = pthread_attr_getschedparam(&source, &scheduler_parameters);
    }
    if (result == 0) {
      result = pthread_attr_setschedpolicy(destination, scheduler_policy);
    }
    if (result == 0) {
      result = pthread_attr_setschedparam(destination, &scheduler_parameters);
    }
    if (result != 0) {
      return result;
    }
  }
  return pthread_attr_setinheritsched(destination, inherit_scheduler);
}

int CopyRequiredThreadAttributes(const pthread_attr_t& source,
                                 pthread_attr_t* destination) noexcept {
  int detach_state = PTHREAD_CREATE_JOINABLE;
  int result = pthread_attr_getdetachstate(&source, &detach_state);
  if (result != 0) {
    return result;
  }
  result = pthread_attr_setdetachstate(destination, detach_state);
  if (result != 0) {
    return result;
  }

  // The retry must retain an explicitly requested guest stack. Falling back
  // to a null/default host attr is unsafe on musl, whose default stack is much
  // smaller than Bionic's and can be exhausted by a single libroblox frame.
  size_t stack_size = 0;
  result = pthread_attr_getstacksize(&source, &stack_size);
  if (result != 0) {
    return result;
  }
  return pthread_attr_setstacksize(destination, stack_size);
}

int ConfigureHostSafeStackFallback(const pthread_attr_t* source,
                                   pthread_attr_t* destination) noexcept {
  size_t guest_stack_size = 0;
  if (source != nullptr) {
    int detach_state = PTHREAD_CREATE_JOINABLE;
    int result = pthread_attr_getdetachstate(source, &detach_state);
    if (result != 0) {
      return result;
    }
    result = pthread_attr_setdetachstate(destination, detach_state);
    if (result != 0) {
      return result;
    }
    result = pthread_attr_getstacksize(source, &guest_stack_size);
    if (result != 0) {
      return result;
    }
  }

  size_t host_default_stack_size = 0;
  int result = pthread_attr_getstacksize(destination, &host_default_stack_size);
  if (result != 0) {
    return result;
  }
  return pthread_attr_setstacksize(
      destination, std::max({guest_stack_size, host_default_stack_size,
                             kBionicLp64FallbackThreadStackSize}));
}

void* RunGuestThread(void* raw_context) noexcept {
  auto* context = static_cast<ThreadStartContext*>(raw_context);
  const ThreadStartContext values = *context;
  delete context;

  if (values.initializer != nullptr) {
    values.initializer();
  }
  return values.start_routine(values.argument);
}

}  // namespace

void ConfigureBionicPthreadThreadInitializer(
    NativeThreadInitializer initializer) noexcept {
  g_thread_initializer.store(initializer, std::memory_order_release);
}

int CreateBionicPthread(pthread_t* thread, const pthread_attr_t* attr,
                        void* (*start_routine)(void*), void* argument) {
  if (thread == nullptr || start_routine == nullptr) {
    return EINVAL;
  }

  auto* context = new (std::nothrow) ThreadStartContext;
  if (context == nullptr) {
    return EAGAIN;
  }
  context->start_routine = start_routine;
  context->argument = argument;
  context->initializer = g_thread_initializer.load(std::memory_order_acquire);

  pthread_attr_t normalized_attr;
  const pthread_attr_t* host_attr = &normalized_attr;
  bool normalized_attr_initialized = false;
  int result = pthread_attr_init(&normalized_attr);
  if (result == 0) {
    normalized_attr_initialized = true;
    if (attr == nullptr) {
      result = pthread_attr_setstacksize(&normalized_attr,
                                         kBionicLp64DefaultThreadStackSize);
    } else {
      result = CopySupportedThreadAttributes(*attr, &normalized_attr);
    }
  }

  if (result == 0) {
    result = pthread_create(thread, host_attr, RunGuestThread, context);
  }
  if (normalized_attr_initialized) {
    pthread_attr_destroy(&normalized_attr);
  }

  // Guest attributes can encode libc-private state that the host rejects only
  // at pthread_create(). First retry explicit attributes with only required
  // portable semantics, preserving their requested stack exactly. A null
  // guest attr skips directly to the host-safe stack fallback.
  if (result == EINVAL) {
    pthread_attr_t portable_attr;
    result = pthread_attr_init(&portable_attr);
    if (result == 0) {
      result = attr == nullptr
                   ? ConfigureHostSafeStackFallback(nullptr, &portable_attr)
                   : CopyRequiredThreadAttributes(*attr, &portable_attr);
      if (result == 0) {
        result =
            pthread_create(thread, &portable_attr, RunGuestThread, context);
      }
      pthread_attr_destroy(&portable_attr);
    }
  }

  // Loading Android DSOs can enlarge the host's static-TLS reservation until
  // an otherwise valid Bionic stack falls below pthread_create's effective
  // minimum. If the exact portable retry is still rejected, grow only the
  // stack while retaining the requested detach state. The larger of the guest
  // request, host default, and musl-safe floor is compatible with POSIX's
  // minimum-stack contract. Failed creates never start the routine, so this
  // call continues to own the context through the final retry.
  if (result == EINVAL && attr != nullptr) {
    pthread_attr_t fallback_attr;
    result = pthread_attr_init(&fallback_attr);
    if (result == 0) {
      result = ConfigureHostSafeStackFallback(attr, &fallback_attr);
      if (result == 0) {
        result =
            pthread_create(thread, &fallback_attr, RunGuestThread, context);
      }
      pthread_attr_destroy(&fallback_attr);
    }
  }
  if (result != 0) {
    delete context;
  }
  return result;
}

}  // namespace mocktail::compat

extern "C" int mocktail_bionic_pthread_create(pthread_t* thread,
                                               const pthread_attr_t* attr,
                                               void* (*start_routine)(void*),
                                               void* argument) {
  return mocktail::compat::CreateBionicPthread(thread, attr, start_routine,
                                               argument);
}
