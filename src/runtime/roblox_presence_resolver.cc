#include "runtime/roblox_presence_resolver.h"

#include <curl/curl.h>

#include <array>
#include <cstdlib>
#include <nlohmann/json.hpp>
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

size_t WriteToString(char* data, size_t size, size_t nmemb, void* userdata) {
  static_cast<std::string*>(userdata)->append(data, size * nmemb);
  return size * nmemb;
}

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

  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    return Invalid("Roblox presence lookup could not initialize a request");
  }

  const nlohmann::json body = {{"userIds", {user_id}}};
  const std::string payload = body.dump();
  std::string response;

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  std::string cookie_header = "Cookie: .ROBLOSECURITY=" + auth_cookie;
  headers = curl_slist_append(headers, cookie_header.c_str());

  curl_easy_setopt(curl, CURLOPT_URL,
                   "https://presence.roblox.com/v1/presence/users");
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteToString);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "X25519:P-256:P-384");
  curl_easy_setopt(curl, CURLOPT_DOH_URL, "https://1.1.1.1/dns-query");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

  const CURLcode result = curl_easy_perform(curl);
  long http_status = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
  curl_slist_free_all(headers);
  if (!cookie_header.empty()) {
    mocktail_rust_secure_zero(cookie_header.data(), cookie_header.size());
  }
  curl_easy_cleanup(curl);

  if (result != CURLE_OK) {
    return Invalid("Roblox presence lookup failed to connect");
  }
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
