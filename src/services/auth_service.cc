#include "services/auth_service.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "services_rust_bridge.h"

namespace mocktail {
namespace services {
namespace {

using internal::AssignSlice;
using internal::DispatchInjectedHttpGet;

AuthSessionStatus StatusFromCode(int32_t code) {
  switch (code) {
    case 0:
      return AuthSessionStatus::kAuthenticated;
    case 1:
      return AuthSessionStatus::kGuest;
    case 2:
      return AuthSessionStatus::kInvalid;
    default:
      return AuthSessionStatus::kUnavailable;
  }
}

}  // namespace

bool AuthService::HasRoblosecurityCookie(const std::string& cookie_header) {
  bool present = false;
  return mocktail_rust_auth_extract_cookie(cookie_header.data(),
                                           cookie_header.size(), &present,
                                           nullptr, 0, nullptr) == 0 &&
         present;
}

std::string AuthService::ExtractRoblosecurityValue(
    std::string_view cookie_header) {
  bool present = false;
  std::string out(cookie_header.size() + 1, '\0');
  size_t out_len = 0;
  if (mocktail_rust_auth_extract_cookie(cookie_header.data(),
                                        cookie_header.size(), &present,
                                        out.data(), out.size(), &out_len) == 0 &&
      present) {
    out.resize(out_len);
    return out;
  }
  return {};
}

bool AuthService::RedactRejectedRoblosecurity(std::string_view cookie_header,
                                              std::string_view rejected_value,
                                              std::string* redacted_header) {
  if (redacted_header == nullptr) {
    return false;
  }
  std::string buffer(cookie_header.size() + 1, '\0');
  size_t out_len = 0;
  const int32_t rc = mocktail_rust_auth_redact_rejected(
      cookie_header.data(), cookie_header.size(), rejected_value.data(),
      rejected_value.size(), buffer.data(), buffer.size(), &out_len);
  if (rc != 0) {
    redacted_header->clear();
    return false;
  }
  buffer.resize(out_len);
  *redacted_header = std::move(buffer);
  return true;
}

AuthSession AuthService::ResolveSession(std::string_view cookie_header,
                                        bool allow_guest) {
  AuthSession session;
  mocktail_rust_auth_resolve_session(
      cookie_header.data(), cookie_header.size(), allow_guest,
      &DispatchInjectedHttpGet, &http_client_,
      [](void* ctx, const MocktailRustAuthSessionResultView* view) {
        auto* out = static_cast<AuthSession*>(ctx);
        if (out == nullptr || view == nullptr) {
          return;
        }
        out->status = StatusFromCode(view->status);
        out->identity.user_id = view->user_id;
        out->identity.username = AssignSlice(view->username);
        out->identity.display_name = AssignSlice(view->display_name);
        out->http_status = static_cast<long>(view->http_status);
        out->error = AssignSlice(view->error);
      },
      &session);
  return session;
}

AuthCookieValidation AuthService::ValidateCookie(
    const std::string& cookie_header) {
  const AuthSession session = ResolveSession(cookie_header, false);
  AuthCookieValidation result;
  result.http_status = session.http_status;
  result.error = session.error;
  switch (session.status) {
    case AuthSessionStatus::kAuthenticated:
      result.status = AuthCookieStatus::kValid;
      break;
    case AuthSessionStatus::kInvalid:
      result.status = AuthCookieStatus::kInvalid;
      break;
    case AuthSessionStatus::kGuest:
    case AuthSessionStatus::kUnavailable:
      result.status = AuthCookieStatus::kUnavailable;
      break;
  }
  return result;
}

}  // namespace services
}  // namespace mocktail
