#include "compat/bionic_sysconf.h"

namespace mocktail::compat {

long BionicSysconf(int name) noexcept {
  return mocktail_bionic_sysconf(name);
}

}  // namespace mocktail::compat
