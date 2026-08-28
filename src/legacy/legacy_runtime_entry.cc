#include <utility>

#include "legacy/legacy_runtime.h"
#include "legacy/legacy_runtime_impl.h"

namespace mocktail::legacy {

int Run(const runtime::CommandLineOptions& options,
        RuntimeDependencies dependencies) {
  return internal::RunLegacy(options, std::move(dependencies));
}

}  // namespace mocktail::legacy
