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

#ifndef MOCKTAIL_COMPAT_BIONIC_SOCKET_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_SOCKET_RUNTIME_H_

#include <sys/socket.h>

extern "C" {

int mocktail_bionic_setsockopt(int socket, int level, int option_name,
                               const void *option_value,
                               socklen_t option_length);

ssize_t mocktail_bionic_sendmsg(int socket, const struct msghdr *message,
                                int flags);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_SOCKET_RUNTIME_H_
