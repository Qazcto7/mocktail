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

#ifndef MOCKTAIL_RUNTIME_WEBVIEW_ROBLOX_COOKIE_H_
#define MOCKTAIL_RUNTIME_WEBVIEW_ROBLOX_COOKIE_H_

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/auth_runtime_composition.h"

namespace mocktail {
namespace runtime {

inline constexpr std::size_t kMaximumWebViewRobloxCookieValueBytes = 16 * 1024;
inline constexpr std::string_view kWebViewRobloxCookieName = ".ROBLOSECURITY";
inline constexpr std::string_view kWebViewRobloxCookieDomain = ".roblox.com";
inline constexpr std::string_view kWebViewRobloxCookiePath = "/";

struct WebViewRobloxCookieResult;

// Move-only credential material prepared for WebKitCookieManager. The value
// contains no name or attributes so the transport cannot alter the fixed
// Roblox-only scope. Its allocation is cleared before release.
class SecureWebViewRobloxCookie final {
 public:
  SecureWebViewRobloxCookie() = default;
  ~SecureWebViewRobloxCookie();

  SecureWebViewRobloxCookie(const SecureWebViewRobloxCookie&) = delete;
  SecureWebViewRobloxCookie& operator=(const SecureWebViewRobloxCookie&) =
      delete;
  SecureWebViewRobloxCookie(SecureWebViewRobloxCookie&& other) noexcept;
  SecureWebViewRobloxCookie& operator=(
      SecureWebViewRobloxCookie&& other) noexcept;

  bool empty() const { return bytes_.empty(); }
  std::size_t size() const { return bytes_.empty() ? 0 : bytes_.size() - 1; }
  std::string_view value() const { return {c_str(), size()}; }
  const char* c_str() const { return bytes_.empty() ? "" : bytes_.data(); }
  SecureWebViewRobloxCookie Clone() const;
  void Clear();

 private:
  explicit SecureWebViewRobloxCookie(std::string_view value);

  std::vector<char> bytes_;

  friend struct WebViewRobloxCookieResult;
  friend WebViewRobloxCookieResult PrepareWebViewRobloxCookie(
      const SecureRobloxCredential& credential);
};

struct WebViewRobloxCookieResult {
  SecureWebViewRobloxCookie cookie;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

// Derives the exact WebKit cookie value from the already validated runtime
// credential. No environment or disk fallback is permitted at this boundary.
// Guest credentials intentionally produce a successful empty cookie.
WebViewRobloxCookieResult PrepareWebViewRobloxCookie(
    const SecureRobloxCredential& credential);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_WEBVIEW_ROBLOX_COOKIE_H_
