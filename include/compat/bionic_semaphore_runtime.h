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

#ifndef MOCKTAIL_COMPAT_BIONIC_SEMAPHORE_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_SEMAPHORE_RUNTIME_H_

#include <semaphore.h>

// Bionic and glibc use different sem_t representations. These exports keep
// host semaphore objects out of guest storage and key them by guest address.
extern "C" {

int mocktail_bionic_sem_init(sem_t* semaphore, int process_shared,
                             unsigned int value);
int mocktail_bionic_sem_destroy(sem_t* semaphore);
int mocktail_bionic_sem_wait(sem_t* semaphore);
int mocktail_bionic_sem_post(sem_t* semaphore);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_SEMAPHORE_RUNTIME_H_
