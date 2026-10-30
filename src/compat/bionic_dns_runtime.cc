#include "compat/bionic_dns_runtime.h"

#include <netdb.h>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace compat {
namespace {

constexpr int kBionicAddressInfoFailure = 4;
constexpr int kBionicAddressInfoMemory = 6;

int BionicAddressInfoError(int host_error) noexcept {
  return mocktail_rust_bionic_eai_error(host_error);
}

addrinfo HostHints(const BionicAddressInfo* hints) noexcept {
  addrinfo host_hints{};
  if (hints != nullptr) {
    host_hints.ai_flags = hints->ai_flags;
    host_hints.ai_family = hints->ai_family;
    host_hints.ai_socktype = hints->ai_socktype;
    host_hints.ai_protocol = hints->ai_protocol;
  }
  return host_hints;
}

bool CopyHostAddressInfo(const addrinfo* host,
                         BionicAddressInfo** result) noexcept {
  BionicAddressInfo* head = nullptr;
  BionicAddressInfo* tail = nullptr;
  for (const addrinfo* current = host; current != nullptr;
       current = current->ai_next) {
    auto* node = static_cast<BionicAddressInfo*>(
        std::calloc(1, sizeof(BionicAddressInfo)));
    if (node == nullptr) {
      BionicFreeAddressInfo(head);
      return false;
    }
    node->ai_flags = current->ai_flags;
    node->ai_family = current->ai_family;
    node->ai_socktype = current->ai_socktype;
    node->ai_protocol = current->ai_protocol;
    node->ai_addrlen = current->ai_addrlen;
    if (current->ai_canonname != nullptr) {
      node->ai_canonname = ::strdup(current->ai_canonname);
      if (node->ai_canonname == nullptr) {
        std::free(node);
        BionicFreeAddressInfo(head);
        return false;
      }
    }
    if (current->ai_addr != nullptr && current->ai_addrlen > 0) {
      node->ai_addr = static_cast<sockaddr*>(std::malloc(current->ai_addrlen));
      if (node->ai_addr == nullptr) {
        std::free(node->ai_canonname);
        std::free(node);
        BionicFreeAddressInfo(head);
        return false;
      }
      std::memcpy(node->ai_addr, current->ai_addr, current->ai_addrlen);
    }
    if (head == nullptr) {
      head = node;
    } else {
      tail->ai_next = node;
    }
    tail = node;
  }
  *result = head;
  return head != nullptr;
}

}  // namespace

static_assert(sizeof(void*) == 8,
              "the current Bionic DNS runtime supports x86-64 only");
static_assert(sizeof(BionicAddressInfo) == 48,
              "Bionic x86-64 addrinfo must occupy 48 bytes");
static_assert(offsetof(BionicAddressInfo, ai_canonname) == 24);
static_assert(offsetof(BionicAddressInfo, ai_addr) == 32);

bool IsBlockedCrashReportUploadHost(std::string_view host) noexcept {
  const std::string s(host);
  return mocktail_rust_is_blocked_crash_host(s.c_str()) == 1;
}

int BionicGetAddressInfo(const char* node, const char* service,
                         const BionicAddressInfo* hints,
                         BionicAddressInfo** result) noexcept {
  if (result == nullptr) {
    return kBionicAddressInfoFailure;
  }
  *result = nullptr;
  if (node != nullptr && IsBlockedCrashReportUploadHost(node)) {
    return kBionicAddressInfoNameNotFound;
  }

  const addrinfo host_hints = HostHints(hints);
  addrinfo* host_result = nullptr;
  const int host_error = ::getaddrinfo(
      node, service, hints != nullptr ? &host_hints : nullptr, &host_result);
  if (host_error != 0) {
    return BionicAddressInfoError(host_error);
  }
  const bool copied = CopyHostAddressInfo(host_result, result);
  ::freeaddrinfo(host_result);
  return copied ? 0 : kBionicAddressInfoMemory;
}

void BionicFreeAddressInfo(BionicAddressInfo* info) noexcept {
  while (info != nullptr) {
    BionicAddressInfo* next = info->ai_next;
    std::free(info->ai_canonname);
    std::free(info->ai_addr);
    std::free(info);
    info = next;
  }
}

hostent* BionicGetHostByName(const char* name) noexcept {
  if (name != nullptr && IsBlockedCrashReportUploadHost(name)) {
    h_errno = HOST_NOT_FOUND;
    return nullptr;
  }
  return ::gethostbyname(name);
}

}  // namespace compat
}  // namespace mocktail

extern "C" int mocktail_bionic_getaddrinfo(
    const char* node, const char* service,
    const mocktail::compat::BionicAddressInfo* hints,
    mocktail::compat::BionicAddressInfo** result) {
  return mocktail::compat::BionicGetAddressInfo(node, service, hints, result);
}

extern "C" void mocktail_bionic_freeaddrinfo(
    mocktail::compat::BionicAddressInfo* info) {
  mocktail::compat::BionicFreeAddressInfo(info);
}

extern "C" hostent* mocktail_bionic_gethostbyname(const char* name) {
  return mocktail::compat::BionicGetHostByName(name);
}
