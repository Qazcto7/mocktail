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

#include "runtime/environment.h"

#include <cstdlib>

namespace mocktail {
namespace runtime {

bool Environment::HasNonEmpty(std::string_view name) const {
  const std::optional<std::string> value = Get(name);
  return value.has_value() && !value->empty();
}

std::string Environment::GetOr(std::string_view name,
                               std::string_view default_value) const {
  const std::optional<std::string> value = Get(name);
  if (!value.has_value() || value->empty()) {
    return std::string(default_value);
  }
  return *value;
}

std::optional<std::string> ProcessEnvironment::Get(
    std::string_view name) const {
  // getenv requires a null-terminated name; std::string also prevents callers
  // from accidentally passing a transient, non-terminated string_view.
  const std::string owned_name(name);
  const char* value = std::getenv(owned_name.c_str());
  if (value == nullptr) {
    return std::nullopt;
  }
  return std::string(value);
}

}  // namespace runtime
}  // namespace mocktail
