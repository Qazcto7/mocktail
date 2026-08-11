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

#include "compat/bionic_atfork_runtime.h"

#include <pthread.h>

namespace mocktail::compat {

int RegisterBionicAtFork(BionicAtForkCallback prepare,
                         BionicAtForkCallback parent,
                         BionicAtForkCallback child,
                         void* dso_handle) noexcept {
  // pthread_atfork preserves the Android/POSIX callback order and is provided
  // by both glibc and musl. Its public contract intentionally has no DSO
  // lifetime hook; see the constraint documented in the public header.
  static_cast<void>(dso_handle);
  return pthread_atfork(prepare, parent, child);
}

}  // namespace mocktail::compat

extern "C" int
mocktail_bionic_register_atfork(mocktail::compat::BionicAtForkCallback prepare,
                                mocktail::compat::BionicAtForkCallback parent,
                                mocktail::compat::BionicAtForkCallback child,
                                void* dso_handle) {
  return mocktail::compat::RegisterBionicAtFork(prepare, parent, child,
                                                dso_handle);
}
