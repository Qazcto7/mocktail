#include "legacy/bionic_runtime_wrappers.h"

#include <netdb.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "legacy/runtime_environment.h"
#include "libc_shim/libc_shim.h"
#include "linker/linker.h"

namespace mocktail::legacy::internal {
namespace {

struct BionicAddrInfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  char* ai_canonname;
  sockaddr* ai_addr;
  BionicAddrInfo* ai_next;
};

static_assert(sizeof(BionicAddrInfo) == 48,
              "unexpected x86_64 bionic addrinfo size");

bool DnsTraceEnabled() { return IsEnabled("MOCKTAIL_DNS_TRACE"); }

addrinfo HostHintsFromBionic(const BionicAddrInfo* hints) {
  addrinfo host_hints{};
  if (hints == nullptr) {
    return host_hints;
  }
  host_hints.ai_flags = hints->ai_flags;
  host_hints.ai_family = hints->ai_family;
  host_hints.ai_socktype = hints->ai_socktype;
  host_hints.ai_protocol = hints->ai_protocol;
  return host_hints;
}

BionicAddrInfo* BionicAddrInfoFromHost(const addrinfo* host) {
  BionicAddrInfo* head = nullptr;
  BionicAddrInfo* tail = nullptr;
  for (const addrinfo* current = host; current != nullptr;
       current = current->ai_next) {
    auto* node =
        static_cast<BionicAddrInfo*>(std::calloc(1, sizeof(BionicAddrInfo)));
    if (node == nullptr) {
      break;
    }
    node->ai_flags = current->ai_flags;
    node->ai_family = current->ai_family;
    node->ai_socktype = current->ai_socktype;
    node->ai_protocol = current->ai_protocol;
    node->ai_addrlen = current->ai_addrlen;
    if (current->ai_canonname != nullptr) {
      node->ai_canonname = ::strdup(current->ai_canonname);
    }
    if (current->ai_addr != nullptr && current->ai_addrlen > 0) {
      node->ai_addr = static_cast<sockaddr*>(std::malloc(current->ai_addrlen));
      if (node->ai_addr != nullptr) {
        std::memcpy(node->ai_addr, current->ai_addr, current->ai_addrlen);
      }
    }
    if (head == nullptr) {
      head = node;
    } else {
      tail->ai_next = node;
    }
    tail = node;
  }
  return head;
}

int MocktailGetaddrinfo(const char* node, const char* service,
                        const BionicAddrInfo* hints, BionicAddrInfo** result) {
  if (result == nullptr) {
    return EAI_FAIL;
  }
  *result = nullptr;
  addrinfo host_hints = HostHintsFromBionic(hints);
  addrinfo* host_result = nullptr;
  const int rc = ::getaddrinfo(
      node, service, hints != nullptr ? &host_hints : nullptr, &host_result);
  if (DnsTraceEnabled()) {
    std::cout << "  [dns] getaddrinfo node="
              << (node != nullptr ? node : "(null)")
              << " service=" << (service != nullptr ? service : "(null)")
              << " family=" << (hints != nullptr ? hints->ai_family : 0)
              << " socktype=" << (hints != nullptr ? hints->ai_socktype : 0)
              << " rc=" << rc
              << " message=" << (rc == 0 ? "ok" : ::gai_strerror(rc)) << '\n';
  }
  if (rc != 0) {
    return rc;
  }
  *result = BionicAddrInfoFromHost(host_result);
  ::freeaddrinfo(host_result);
  return *result != nullptr ? 0 : EAI_MEMORY;
}

void MocktailFreeaddrinfo(BionicAddrInfo* info) {
  while (info != nullptr) {
    BionicAddrInfo* next = info->ai_next;
    std::free(info->ai_canonname);
    std::free(info->ai_addr);
    std::free(info);
    info = next;
  }
}

hostent* MocktailGethostbyname(const char* name) {
  hostent* result = ::gethostbyname(name);
  if (DnsTraceEnabled()) {
    std::cout << "  [dns] gethostbyname name="
              << (name != nullptr ? name : "(null)")
              << " result=" << reinterpret_cast<void*>(result) << '\n';
  }
  return result;
}

int MocktailMprotect(void* address, std::size_t length, int protection) {
  if (address == nullptr || length == 0) {
    errno = EINVAL;
    return -1;
  }
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size <= 0) {
    errno = EINVAL;
    return -1;
  }
  const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(address);
  const std::uintptr_t page_mask = static_cast<std::uintptr_t>(page_size) - 1;
  const std::uintptr_t page_start = start & ~page_mask;
  const std::uintptr_t end = start + length;
  if (end < start) {
    errno = EINVAL;
    return -1;
  }
  const std::uintptr_t page_end = (end + page_mask) & ~page_mask;
  if (page_end < page_start) {
    errno = EINVAL;
    return -1;
  }
  return ::mprotect(reinterpret_cast<void*>(page_start),
                    static_cast<std::size_t>(page_end - page_start),
                    protection);
}

}  // namespace

void RegisterBionicDnsWrappers() {
  linker::RegisterSymbol("getaddrinfo",
                         reinterpret_cast<void*>(MocktailGetaddrinfo));
  linker::RegisterSymbol("freeaddrinfo",
                         reinterpret_cast<void*>(MocktailFreeaddrinfo));
  linker::RegisterSymbol("gethostbyname",
                         reinterpret_cast<void*>(MocktailGethostbyname));
}

void RegisterBionicPathWrappers() {
  linker::RegisterSymbol("open", reinterpret_cast<void*>(mocktail_open));
  linker::RegisterSymbol("__open_2",
                         reinterpret_cast<void*>(mocktail___open_2));
  linker::RegisterSymbol("fopen", reinterpret_cast<void*>(mocktail_fopen));
  linker::RegisterSymbol("access", reinterpret_cast<void*>(mocktail_access));
  linker::RegisterSymbol("stat", reinterpret_cast<void*>(mocktail_stat));
  linker::RegisterSymbol("lstat", reinterpret_cast<void*>(mocktail_lstat));
  linker::RegisterSymbol("statvfs", reinterpret_cast<void*>(mocktail_statvfs));
  linker::RegisterSymbol("statfs", reinterpret_cast<void*>(mocktail_statfs));
  linker::RegisterSymbol("mkdir", reinterpret_cast<void*>(mocktail_mkdir));
  linker::RegisterSymbol("opendir", reinterpret_cast<void*>(mocktail_opendir));
  linker::RegisterSymbol("rename", reinterpret_cast<void*>(mocktail_rename));
  linker::RegisterSymbol("unlink", reinterpret_cast<void*>(mocktail_unlink));
  linker::RegisterSymbol("rmdir", reinterpret_cast<void*>(mocktail_rmdir));
  linker::RegisterSymbol("realpath",
                         reinterpret_cast<void*>(mocktail_realpath));
  linker::RegisterSymbol("readlink",
                         reinterpret_cast<void*>(mocktail_readlink));
  linker::RegisterSymbol("__readlink_chk",
                         reinterpret_cast<void*>(mocktail___readlink_chk));
}

void RegisterBionicMemoryWrappers() {
  linker::RegisterSymbol("mprotect", reinterpret_cast<void*>(MocktailMprotect));
}

}  // namespace mocktail::legacy::internal
