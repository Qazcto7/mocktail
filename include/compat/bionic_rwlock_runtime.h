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

#ifndef MOCKTAIL_COMPAT_BIONIC_RWLOCK_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_RWLOCK_RUNTIME_H_

#include <pthread.h>

// Bionic and glibc pthread_rwlock_t storage is not ABI-compatible. The guest
// address is an opaque key; the host object lives entirely in this runtime.
extern "C" {

int mocktail_bionic_pthread_rwlock_init(pthread_rwlock_t* rwlock,
                                        const pthread_rwlockattr_t* attr);
int mocktail_bionic_pthread_rwlock_destroy(pthread_rwlock_t* rwlock);
int mocktail_bionic_pthread_rwlock_rdlock(pthread_rwlock_t* rwlock);
int mocktail_bionic_pthread_rwlock_wrlock(pthread_rwlock_t* rwlock);
int mocktail_bionic_pthread_rwlock_unlock(pthread_rwlock_t* rwlock);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_RWLOCK_RUNTIME_H_
