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

#ifndef MOCKTAIL_COMPAT_BIONIC_HOST_LIBC_RUNTIME_H_
#define MOCKTAIL_COMPAT_BIONIC_HOST_LIBC_RUNTIME_H_

#include <sys/uio.h>

#include <cstddef>
#include <cstdint>

namespace mocktail::compat {

// Android x86-64's malloc.h declares ten size_t fields in this order. This is
// not the host's struct mallinfo: glibc's legacy type uses int,
// and musl exposes no allocator-telemetry API. On hosts without a compatible
// size_t-based telemetry API, BionicMallinfo returns an all-zero "unknown"
// snapshot. Callers must not interpret that fallback as proof of zero usage.
struct BionicMallinfoSnapshot {
  size_t arena = 0;
  size_t ordblks = 0;
  size_t smblks = 0;
  size_t hblks = 0;
  size_t hblkhd = 0;
  size_t usmblks = 0;
  size_t fsmblks = 0;
  size_t uordblks = 0;
  size_t fordblks = 0;
  size_t keepcost = 0;
};

struct BionicLocaleState;
using BionicLocale = BionicLocaleState*;
using BionicThreadDestructor = void (*)(void*);

// Do not use the host socket structs here. Although glibc happens to match
// Android LP64, musl declares cmsg_len and msg_controllen as 32-bit socklen_t.
// Bionic x86-64 uses size_t for both, as audited from the vendored
// bionic/libc/include/sys/socket.h.
struct BionicMessageHeader {
  void* msg_name = nullptr;
  uint32_t msg_namelen = 0;
  iovec* msg_iov = nullptr;
  size_t msg_iovlen = 0;
  void* msg_control = nullptr;
  size_t msg_controllen = 0;
  int msg_flags = 0;
};

struct BionicControlMessageHeader {
  size_t cmsg_len = 0;
  int cmsg_level = 0;
  int cmsg_type = 0;
};

// Implements Android's exported CMSG_NXTHDR helper over the explicit Bionic
// x86-64 msghdr/cmsghdr layout above. Malformed or truncated control buffers
// fail closed with nullptr.
BionicControlMessageHeader* BionicCmsgNextHeader(
    BionicMessageHeader* message, BionicControlMessageHeader* current) noexcept;

// Registers one destructor for the current thread using libstdc++'s Itanium
// C++ ABI implementation. That implementation is present on both supported
// glibc and musl toolchains and preserves destructor execution at thread exit.
int BionicCxaThreadAtExit(BionicThreadDestructor destructor, void* argument,
                          void* dso_handle) noexcept;

// Fills the complete buffer from the Linux kernel RNG. The implementation
// falls back to /dev/urandom only when getrandom is unavailable or blocked and
// aborts rather than returning predictable or partially initialized bytes.
void BionicArc4RandomBuffer(void* buffer, size_t size) noexcept;

BionicMallinfoSnapshot BionicMallinfo() noexcept;
bool BionicMallinfoHasHostTelemetry() noexcept;

// Formats one Linux errno value using Bionic's POSIX strerror_r contract.
// Unlike glibc's GNU variant, success is reported as zero; truncation returns
// -1 and sets errno to ERANGE while preserving the caller's errno on success.
int BionicStrError(int error_number, char* buffer, size_t buffer_size) noexcept;

// Bionic supports only C and C.UTF-8, whose integer parsing is identical. A
// host C locale is installed only for the duration of each call, so ambient
// process locale cannot change guest parsing and a Bionic locale pointer is
// never mistaken for an incompatible host locale_t.
long long BionicStrToLongLongLocale(const char* text, char** end, int base,
                                    BionicLocale locale) noexcept;
unsigned long long BionicStrToUnsignedLongLongLocale(
    const char* text, char** end, int base, BionicLocale locale) noexcept;

}  // namespace mocktail::compat

extern "C" {

mocktail::compat::BionicControlMessageHeader* mocktail_bionic_cmsg_nxthdr(
    mocktail::compat::BionicMessageHeader* message,
    mocktail::compat::BionicControlMessageHeader* current);
int mocktail_bionic_cxa_thread_atexit_impl(
    mocktail::compat::BionicThreadDestructor destructor, void* argument,
    void* dso_handle);
void mocktail_bionic_arc4random_buf(void* buffer, size_t size);
mocktail::compat::BionicMallinfoSnapshot mocktail_bionic_mallinfo();
int mocktail_bionic_strerror_r(int error_number, char* buffer,
                               size_t buffer_size);
long long mocktail_bionic_strtoll_l(const char* text, char** end, int base,
                                    mocktail::compat::BionicLocale locale);
unsigned long long mocktail_bionic_strtoull_l(
    const char* text, char** end, int base,
    mocktail::compat::BionicLocale locale);

}  // extern "C"

#endif  // MOCKTAIL_COMPAT_BIONIC_HOST_LIBC_RUNTIME_H_
