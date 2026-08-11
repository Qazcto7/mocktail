// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#ifndef MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_
#define MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_

#include <string>

#include "runtime/environment.h"
#include "runtime/runtime_paths.h"

namespace mocktail {
namespace runtime {

struct PayloadUpdatePreflightResult {
  bool attempted = false;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

PayloadUpdatePreflightResult RunPayloadUpdatePreflight(
    const Environment& environment, const RuntimePaths& paths);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_
