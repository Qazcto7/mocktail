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

#ifndef MOCKTAIL_COMPAT_BIONIC_ATFORK_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_ATFORK_RUNTIME_H_

namespace mocktail::compat {

using BionicAtForkCallback = void (*)(void);

// Registers Android's __register_atfork callback contract with the host
// pthread runtime. Bionic associates registrations with dso_handle and
// removes them when that DSO unloads. POSIX pthread_atfork has no matching
// unregister operation, so the host bridge accepts dso_handle for ABI
// compatibility but cannot use it for cleanup.
//
// Callback code must remain mapped for every later fork. In practice, a guest
// DSO that has registered callbacks must stay loaded until process exit;
// unloading is safe only when the process guarantees that it will never fork
// again.
int RegisterBionicAtFork(BionicAtForkCallback prepare,
                         BionicAtForkCallback parent,
                         BionicAtForkCallback child, void* dso_handle) noexcept;

}  // namespace mocktail::compat

extern "C" {

// Exact LP64 Android/Bionic __register_atfork signature. The prefixed host
// symbol is exported to the guest as "__register_atfork" by synthetic libc.so.
int mocktail_bionic_register_atfork(
    mocktail::compat::BionicAtForkCallback prepare,
    mocktail::compat::BionicAtForkCallback parent,
    mocktail::compat::BionicAtForkCallback child, void* dso_handle);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_ATFORK_RUNTIME_H_
