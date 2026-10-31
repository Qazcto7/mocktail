#include "compat/bionic_sysconf.h"

#include <errno.h>
#include <unistd.h>

#include "mocktail/mocktail_rust.h"

namespace mocktail::compat {

long BionicSysconf(int name) noexcept {
  int32_t standard_sc = 0;
  int64_t fixed_val = 0;
  const int32_t kind = mocktail_rust_bionic_sysconf_translate_name(
      name, &standard_sc, &fixed_val);
  if (kind == 1) {
    return static_cast<long>(fixed_val);
  }
  if (kind == 0) {
    switch (static_cast<BionicSysconfName>(name)) {
      case BionicSysconfName::kArgMax:
        return ::sysconf(_SC_ARG_MAX);
      case BionicSysconfName::kChildMax:
        return ::sysconf(_SC_CHILD_MAX);
      case BionicSysconfName::kOpenMax:
        return ::sysconf(_SC_OPEN_MAX);
      case BionicSysconfName::kIovMax:
        return ::sysconf(_SC_IOV_MAX);
      case BionicSysconfName::kPageSize:
      case BionicSysconfName::kPageSizeAlias:
        return ::sysconf(_SC_PAGESIZE);
      case BionicSysconfName::kProcessorsConfigured:
        return ::sysconf(_SC_NPROCESSORS_CONF);
      case BionicSysconfName::kProcessorsOnline:
        return ::sysconf(_SC_NPROCESSORS_ONLN);
      case BionicSysconfName::kPhysicalPages:
        return ::sysconf(_SC_PHYS_PAGES);
      case BionicSysconfName::kAvailablePhysicalPages:
        return ::sysconf(_SC_AVPHYS_PAGES);
      default:
        break;
    }
  }

  errno = EINVAL;
  return -1;
}

} // namespace mocktail::compat

extern "C" long mocktail_bionic_sysconf(int name) {
  return mocktail::compat::BionicSysconf(name);
}
