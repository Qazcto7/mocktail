#include "services/auth_service.h"
#include "mocktail/mocktail_rust.h"

#define JSON_NOEXCEPTION 1
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace mocktail {
namespace services {
namespace {

constexpr std::string_view kAuthenticatedUserUrl =
    "https://users.roblox.com/v1/users/authenticated";

struct ExtractedCookie {
  bool present = false;
  std::string value;
};

ExtractedCookie ExtractCookie(std::string_view header) {
  std::string buf(header.size() + 1, '\0');
  size_t out_len = 0;
  bool present = false;
  if (mocktail_rust_auth_extract_cookie(
          header.data(), header.size(), &present,
          buf.data(), buf.size(), &out_len) == 0 &&
      present) {
    buf.resize(out_len);
    return {true, std::move(buf)};
  }
  return {present, {}};
}

bool IsSafeCookieValue(std::string_view value) {
  return mocktail_rust_auth_is_safe_cookie_value(value.data(), value.size());
}

bool ParseIdentity(const std::string& body, AuthIdentity* identity) {
  int64_t user_id = -1;
  std::array<char, 256> name_buf{};
  std::array<char, 256> display_buf{};
  if (mocktail_rust_auth_parse_identity(
          body.data(), body.size(), &user_id,
          name_buf.data(), name_buf.size(),
          display_buf.data(), display_buf.size()) != 0) {
    return false;
  }
  identity->user_id = user_id;
  identity->username = name_buf.data();
  identity->display_name = display_buf.data();
  return true;
}

}  // namespace

bool AuthService::HasRoblosecurityCookie(const std::string& cookie_header) {
  return ExtractCookie(cookie_header).present;
}

std::string AuthService::ExtractRoblosecurityValue(
    std::string_view cookie_header) {
  return ExtractCookie(cookie_header).value;
}

bool AuthService::RedactRejectedRoblosecurity(std::string_view cookie_header,
                                              std::string_view rejected_value,
                                              std::string* redacted_header) {
  if (redacted_header == nullptr) {
    return false;
  }
  redacted_header->clear();
  if (rejected_value.empty()) {
    return false;
  }
  std::string out_buf(cookie_header.size() + 1, '\0');
  size_t out_len = 0;
  if (mocktail_rust_auth_redact_rejected(
          cookie_header.data(), cookie_header.size(),
          rejected_value.data(), rejected_value.size(),
          out_buf.data(), out_buf.size(), &out_len) != 0) {
    return false;
  }
  out_buf.resize(out_len);
  *redacted_header = std::move(out_buf);
  return true;
}

AuthSession AuthService::ResolveSession(std::string_view cookie_header,
                                        bool allow_guest) {
  AuthSession session;
  const ExtractedCookie cookie = ExtractCookie(cookie_header);
  if (!cookie.present) {
    if (allow_guest) {
      session.status = AuthSessionStatus::kGuest;
      return session;
    }
    session.status = AuthSessionStatus::kInvalid;
    session.error = "missing .ROBLOSECURITY cookie";
    return session;
  }
  if (!IsSafeCookieValue(cookie.value)) {
    session.status = AuthSessionStatus::kInvalid;
    session.error = "invalid .ROBLOSECURITY cookie";
    return session;
  }

  HttpRequest request;
  request.url = std::string(kAuthenticatedUserUrl);
  request.timeout_ms = 15000;
  request.maximum_body_bytes = 1024 * 1024;
  // Never forward a raw security cookie to another origin through an
  // unexpected redirect.
  request.follow_redirects = false;
  request.headers.push_back("Accept: application/json");
  request.headers.push_back("Cookie: .ROBLOSECURITY=" +
                            std::string(cookie.value));
  HttpResponse response = http_client_.Get(request);
  session.http_status = response.status_code;
  if (!response.transport_ok) {
    session.status = AuthSessionStatus::kUnavailable;
    // Do not propagate backend error strings: a custom HttpClient may include
    // request headers in them, which would disclose the security cookie.
    session.error = "authentication service unavailable";
  } else if (response.status_code == 200) {
    if (!ParseIdentity(response.body, &session.identity)) {
      session.status = AuthSessionStatus::kUnavailable;
      session.error = "invalid authenticated-user response";
      return session;
    }
    session.status = AuthSessionStatus::kAuthenticated;
  } else if (response.status_code == 401 || response.status_code == 403) {
    session.status = AuthSessionStatus::kInvalid;
    session.error = "authentication rejected";
  } else {
    session.status = AuthSessionStatus::kUnavailable;
    session.error = "unexpected authentication HTTP status";
  }
  return session;
}

AuthCookieValidation AuthService::ValidateCookie(
    const std::string& cookie_header) {
  const AuthSession session = ResolveSession(cookie_header, false);
  AuthCookieValidation validation;
  validation.http_status = session.http_status;
  validation.error = session.error;
  switch (session.status) {
    case AuthSessionStatus::kAuthenticated:
      validation.status = AuthCookieStatus::kValid;
      break;
    case AuthSessionStatus::kGuest:
    case AuthSessionStatus::kInvalid:
      validation.status = AuthCookieStatus::kInvalid;
      break;
    case AuthSessionStatus::kUnavailable:
      validation.status = AuthCookieStatus::kUnavailable;
      break;
  }
  return validation;
}

}  // namespace services
}  // namespace mocktail
