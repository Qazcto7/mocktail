#ifndef MOCKTAIL_LEGACY_LEGACY_RUNTIME_IMPL_H_
#define MOCKTAIL_LEGACY_LEGACY_RUNTIME_IMPL_H_

#include "legacy/legacy_runtime.h"

namespace mocktail::legacy::internal {

int RunLegacy(const runtime::CommandLineOptions& options,
              RuntimeDependencies dependencies);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_LEGACY_RUNTIME_IMPL_H_
