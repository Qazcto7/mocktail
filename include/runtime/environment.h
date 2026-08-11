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

#ifndef MOCKTAIL_RUNTIME_ENVIRONMENT_H_
#define MOCKTAIL_RUNTIME_ENVIRONMENT_H_

#include <optional>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {

// Read-only environment abstraction. Production code uses ProcessEnvironment;
// tests can provide a deterministic map-backed implementation.
class Environment {
 public:
  virtual ~Environment() = default;

  virtual std::optional<std::string> Get(std::string_view name) const = 0;

  bool HasNonEmpty(std::string_view name) const;
  std::string GetOr(std::string_view name,
                    std::string_view default_value) const;
};

class ProcessEnvironment final : public Environment {
 public:
  std::optional<std::string> Get(std::string_view name) const override;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ENVIRONMENT_H_
