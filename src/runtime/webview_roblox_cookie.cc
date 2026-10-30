#include "runtime/webview_roblox_cookie.h"
#include "mocktail/mocktail_rust.h"

#include <algorithm>
#include <utility>

namespace mocktail {
namespace runtime {

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
  if (!bytes_.empty()) {
    mocktail_rust_secure_zero(reinterpret_cast<uint8_t*>(bytes_.data()),
                              bytes_.size());
    bytes_.clear();
  }
}

WebViewRobloxCookieResult PrepareWebViewRobloxCookie(
    const SecureRobloxCredential& credential) {
  if (credential.empty()) {
    return {};
  }
  const std::string_view header = credential.view();
  std::string null_terminated_header(header);
  std::string extracted(kMaximumWebViewRobloxCookieValueBytes + 1, '\0');
  size_t extracted_len = 0;
  const int status = mocktail_rust_parse_roblox_cookie(
      null_terminated_header.c_str(),
      extracted.data(),
      extracted.size(),
      &extracted_len);
  if (status == 0 && extracted_len > 0) {
    extracted.resize(extracted_len);
    SecureWebViewRobloxCookie cookie(extracted);
    mocktail_rust_secure_zero(reinterpret_cast<uint8_t*>(extracted.data()),
                              extracted.size());
    return {std::move(cookie), {}};
  }
  return {{}, "WebView .ROBLOSECURITY value is empty, oversized, or unsafe"};
}

}  // namespace runtime
}  // namespace mocktail
