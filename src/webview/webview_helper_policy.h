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

#ifndef MOCKTAIL_WEBVIEW_WEBVIEW_HELPER_POLICY_H_
#define MOCKTAIL_WEBVIEW_WEBVIEW_HELPER_POLICY_H_

#include <jsc/jsc.h>

#include <cstddef>
#include <string>
#include <string_view>

namespace mocktail {
namespace webview {

inline constexpr std::size_t kMaximumHybridCommandBytes = 64 * 1024;
inline constexpr char kExecuteRobloxHandler[] = "executeRoblox";
inline constexpr char kRobloxWkHybridHandler[] = "RobloxWKHybrid";
inline constexpr char kCompatibilityHandler[] = "mocktailRobloxBridge";

enum class CaptchaEventType {
  kShown,
  kSuccess,
};

struct CaptchaEvent {
  CaptchaEventType type = CaptchaEventType::kShown;
  std::string callback_id;
};

struct UriPolicyResult {
  bool allowed = false;
  bool privileged_bridge_allowed = false;
  std::string scheme = "invalid";
  std::string host = "none";
};

const char* AndroidBridgeSource();
std::string BuildRobloxAndroidUserAgent();
std::string BoundedLogToken(const char* value, std::string_view fallback);
UriPolicyResult EvaluateNavigationUri(const char* uri);
const char* CaptchaEventName(CaptchaEventType type);
bool ExtractExecuteRobloxCommand(JSCValue* value, std::string* command);
bool ExtractRobloxWkHybridCommand(JSCValue* value, std::string* command);
bool ParseCaptchaEvent(std::string_view command, CaptchaEvent* event);
std::string BuildCallbackScript(std::string_view callback_id);

}  // namespace webview
}  // namespace mocktail

#endif  // MOCKTAIL_WEBVIEW_WEBVIEW_HELPER_POLICY_H_
