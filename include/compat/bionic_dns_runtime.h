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

#ifndef MOCKTAIL_COMPAT_BIONIC_DNS_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_DNS_RUNTIME_H_

#include <netdb.h>
#include <sys/socket.h>

#include <cstdint>
#include <string_view>

namespace mocktail {
namespace compat {

// Android x86-64 orders ai_canonname before ai_addr, unlike glibc. Keep the
// guest layout explicit so DNS results never cross the ABI boundary as a host
// addrinfo.
struct BionicAddressInfo {
  int ai_flags = 0;
  int ai_family = 0;
  int ai_socktype = 0;
  int ai_protocol = 0;
  socklen_t ai_addrlen = 0;
  char* ai_canonname = nullptr;
  sockaddr* ai_addr = nullptr;
  BionicAddressInfo* ai_next = nullptr;
};

constexpr int kBionicAddressInfoNameNotFound = 8;

// Matches only upload infrastructure embedded in the supported Roblox
// payloads (plus Backtrace's public service suffix). Ordinary Roblox API,
// asset, auth, and game-session hosts are outside this policy.
bool IsBlockedCrashReportUploadHost(std::string_view host) noexcept;

int BionicGetAddressInfo(const char* node, const char* service,
                         const BionicAddressInfo* hints,
                         BionicAddressInfo** result) noexcept;
void BionicFreeAddressInfo(BionicAddressInfo* info) noexcept;
hostent* BionicGetHostByName(const char* name) noexcept;

}  // namespace compat
}  // namespace mocktail

extern "C" {

int mocktail_bionic_getaddrinfo(
    const char* node, const char* service,
    const mocktail::compat::BionicAddressInfo* hints,
    mocktail::compat::BionicAddressInfo** result);
void mocktail_bionic_freeaddrinfo(mocktail::compat::BionicAddressInfo* info);
hostent* mocktail_bionic_gethostbyname(const char* name);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_DNS_RUNTIME_H_
