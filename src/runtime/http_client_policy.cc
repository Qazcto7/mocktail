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

#include "runtime/http_client_policy.h"

#define JSON_NOEXCEPTION 1
#include <array>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {
namespace {

struct ClientSetting {
  std::string_view name;
  std::string_view value;
};

constexpr std::array<ClientSetting, 3> kHttpClientSettings = {{
    // The server-controlled RuntimeMutexRv backend defaults to disabled in
    // libroblox.so. Keep that native fallback on the compatibility runtime:
    // profiling shows the Rv path repeatedly crossing Bionic mutex/TLS ABI
    // adapters from the HttpClient retry worker.
    {"FFlagUseRuntimeMutexRvHttpClient", "False"},
    // Streaming requests cannot be replayed safely and otherwise remain in
    // the native retry tree after a transport failure.
    {"DFFlagHttpClientSkipRetryForStreamingRequests", "True"},
    // Preserve explicit retry counts and native gamejoin 429/503 policies,
    // but do not make every LuaApp request retry by default.
    {"FFlagLuaAppDefaultHttpRetry", "False"},
}};

}  // namespace

bool MergeHttpClientSettingsOverrides(std::string_view base_json,
                                      std::string* merged_json,
                                      std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "HttpClient settings output is required";
    }
    return false;
  }

  nlohmann::json overrides = nlohmann::json::parse(
      base_json.empty() ? "{}" : base_json, nullptr, false, true);
  if (overrides.is_discarded() || !overrides.is_object()) {
    if (error != nullptr) {
      *error = "client-settings overrides must be a JSON object";
    }
    return false;
  }

  for (const ClientSetting& setting : kHttpClientSettings) {
    overrides[std::string(setting.name)] = std::string(setting.value);
  }
  *merged_json = overrides.dump();
  return true;
}

}  // namespace runtime
}  // namespace mocktail
