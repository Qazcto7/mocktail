#include "runtime/roblox_presence_resolver.h"

#include <array>
#include <cstdlib>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"
#include "runtime/environment.h"
#include "runtime/roblox_cookie_store.h"
#include "runtime/runtime_paths.h"

namespace mocktail {
namespace runtime {
namespace {

Status Invalid(std::string message) {
  return Status::Error(StatusCode::kInvalidArgument, std::move(message));
}

struct PresenceHttpCapture {
  std::string body;
  std::string error;
  long status_code = 0;
};

}  // namespace

std::string ReadStoredRoblosecurityCookie(
    std::shared_ptr<RobloxSecretStore> secrets) {
  const ProcessEnvironment environment;
  const RuntimePaths paths = RuntimePaths::FromEnvironment(environment);
  if (secrets == nullptr) secrets = OpenRobloxSecretStore();
  StoredCookie cookie;
  if (environment.HasNonEmpty("MOCKTAIL_ROBLOX_COOKIES")) {
    cookie.status = StoredCookieStatus::kFound;
    cookie.value = environment.GetOr("MOCKTAIL_ROBLOX_COOKIES", "");
  } else if (environment.HasNonEmpty("MOCKTAIL_COOKIE_FILE")) {
    cookie = ReadRobloxCookieFile(environment.GetOr("MOCKTAIL_COOKIE_FILE", ""),
                                  true);
  } else {
    cookie = LoadManagedRobloxCookie(paths.cookie_file(), *secrets);
  }
  if (cookie.status != StoredCookieStatus::kFound) return {};
  std::string value(cookie.value.size() + 1, '\0');
  const int32_t rc = mocktail_rust_presence_extract_cookie(
      cookie.value.c_str(), value.data(), value.size());
  if (!cookie.value.empty()) {
    mocktail_rust_secure_zero(cookie.value.data(), cookie.value.size());
  }
  if (rc != 0) {
    if (!value.empty()) {
      mocktail_rust_secure_zero(value.data(), value.size());
    }
    return {};
  }
  value.resize(std::char_traits<char>::length(value.c_str()));
  return value;
}

Status ResolveFollowUserPlace(int64_t user_id, const std::string& auth_cookie,
                              ResolvedFollowUserPlace* out) {
  if (out == nullptr || user_id <= 0) {
    return Invalid("Roblox presence lookup requires a positive userId");
  }
  if (auth_cookie.empty()) {
    return Invalid("Roblox presence lookup requires an authenticated session");
  }

  static constexpr std::string_view kPresenceUrl =
      "https://presence.roblox.com/v1/presence/users";
  static constexpr std::string_view kJsonContentType =
      "Content-Type: application/json";
  const std::string payload =
      "{\"userIds\":[" + std::to_string(user_id) + "]}";
  std::string cookie_header = "Cookie: .ROBLOSECURITY=" + auth_cookie;
  const std::array<MocktailRustStrSlice, 2> headers = {
      MocktailRustStrSlice{kJsonContentType.data(), kJsonContentType.size()},
      MocktailRustStrSlice{cookie_header.data(), cookie_header.size()},
  };

  MocktailRustServiceHttpRequestView view{};
  view.is_post = true;
  view.url = {kPresenceUrl.data(), kPresenceUrl.size()};
  view.body = {payload.data(), payload.size()};
  view.headers_ptr = headers.data();
  view.headers_len = headers.size();
  view.ca_bundle = {"", 0};
  view.timeout_ms = 10000;
  view.max_redirects = 0;
  view.max_response_bytes = 512 * 1024;
  view.max_attempts = 1;
  view.allow_local_socks5_fallback = false;
  view.fallback_env_ca_bundle = true;
  view.use_runtime_env_proxy = true;

  PresenceHttpCapture capture;
  const bool ok = mocktail_rust_services_http_perform(
      &view,
      [](void* ctx, int32_t status_code, const char* body_ptr, size_t body_len,
         const MocktailRustStrSlice* /*headers_ptr*/, size_t /*headers_len*/,
         const char* error_ptr, size_t error_len, bool /*tls_cert_error*/) {
        auto* out_cap = static_cast<PresenceHttpCapture*>(ctx);
        out_cap->status_code = static_cast<long>(status_code);
        if (body_ptr != nullptr && body_len > 0) {
          out_cap->body.assign(body_ptr, body_len);
        }
        if (error_ptr != nullptr && error_len > 0) {
          out_cap->error.assign(error_ptr, error_len);
        }
      },
      &capture);
  if (!cookie_header.empty()) {
    mocktail_rust_secure_zero(cookie_header.data(), cookie_header.size());
  }

  if (!ok || !capture.error.empty()) {
    return Invalid("Roblox presence lookup failed to connect");
  }
  const long http_status = capture.status_code;
  const std::string& response = capture.body;
  if (http_status != 200) {
    return Invalid("Roblox presence lookup was rejected (status " +
                   std::to_string(http_status) + ")");
  }

  int64_t place_id = 0;
  std::array<char, 256> game_id{};
  std::array<char, 256> err_buf{};
  const int32_t parse_rc = mocktail_rust_presence_parse_follow_response(
      response.c_str(), &place_id, game_id.data(), game_id.size(),
      err_buf.data(), err_buf.size());
  if (parse_rc != 0) {
    return Invalid(err_buf.data());
  }
  out->place_id = place_id;
  out->game_instance_id = game_id.data();
  return Status::Ok();
}

}  // namespace runtime
}  // namespace mocktail
