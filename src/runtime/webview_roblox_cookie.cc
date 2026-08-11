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

#include "runtime/webview_roblox_cookie.h"

#include <algorithm>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

constexpr std::string_view kCanonicalPrefix = ".ROBLOSECURITY=";

bool IsCookieOctet(unsigned char byte) {
  return byte == 0x21 || (byte >= 0x23 && byte <= 0x2b) ||
         (byte >= 0x2d && byte <= 0x3a) || (byte >= 0x3c && byte <= 0x5b) ||
         (byte >= 0x5d && byte <= 0x7e);
}

}  // namespace

SecureWebViewRobloxCookie::SecureWebViewRobloxCookie(std::string_view value) {
  bytes_.assign(value.begin(), value.end());
  bytes_.push_back('\0');
}

SecureWebViewRobloxCookie::~SecureWebViewRobloxCookie() { Clear(); }

SecureWebViewRobloxCookie::SecureWebViewRobloxCookie(
    SecureWebViewRobloxCookie&& other) noexcept
    : bytes_(std::move(other.bytes_)) {}

SecureWebViewRobloxCookie& SecureWebViewRobloxCookie::operator=(
    SecureWebViewRobloxCookie&& other) noexcept {
  if (this != &other) {
    Clear();
    bytes_ = std::move(other.bytes_);
  }
  return *this;
}

SecureWebViewRobloxCookie SecureWebViewRobloxCookie::Clone() const {
  return SecureWebViewRobloxCookie(value());
}

void SecureWebViewRobloxCookie::Clear() {
  volatile char* byte = bytes_.empty() ? nullptr : bytes_.data();
  for (std::size_t index = 0; index < bytes_.size(); ++index) {
    byte[index] = '\0';
  }
  bytes_.clear();
}

WebViewRobloxCookieResult PrepareWebViewRobloxCookie(
    const SecureRobloxCredential& credential) {
  if (credential.empty()) {
    return {};
  }
  const std::string_view header = credential.view();
  if (header.size() < kCanonicalPrefix.size() ||
      header.compare(0, kCanonicalPrefix.size(), kCanonicalPrefix) != 0) {
    return {{}, "WebView credential is not a canonical .ROBLOSECURITY header"};
  }
  const std::string_view value = header.substr(kCanonicalPrefix.size());
  if (value.empty() || value.size() > kMaximumWebViewRobloxCookieValueBytes ||
      !std::all_of(value.begin(), value.end(), [](char byte) {
        return IsCookieOctet(static_cast<unsigned char>(byte));
      })) {
    return {{}, "WebView .ROBLOSECURITY value is empty, oversized, or unsafe"};
  }
  return {SecureWebViewRobloxCookie(value), {}};
}

}  // namespace runtime
}  // namespace mocktail
