#include "runtime/roblox_place_metadata.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/environment.h"
#include "runtime/runtime_config.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr std::size_t kMaximumRobloxApiBytes = 512U * 1024U;
constexpr std::chrono::seconds kPlaceMetadataRetryBase{10};
constexpr std::chrono::seconds kPlaceMetadataRetryMaximum{300};

struct BoundedResponse {
  std::string body;
  bool exceeded = false;
};

std::once_flag g_curl_init_once;
CURLcode g_curl_init_status = CURLE_FAILED_INIT;

void InitializeCurl() {
  g_curl_init_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

size_t WriteHttpResponse(char* data, size_t size, size_t count,
                         void* user_data) {
  auto* response = static_cast<BoundedResponse*>(user_data);
  if (response == nullptr || data == nullptr ||
      (count != 0 && size > std::numeric_limits<size_t>::max() / count)) {
    return 0;
  }
  const std::size_t bytes = size * count;
  if (bytes > kMaximumRobloxApiBytes ||
      response->body.size() > kMaximumRobloxApiBytes - bytes) {
    response->exceeded = true;
    return 0;
  }
  response->body.append(data, bytes);
  return bytes;
}

bool NeedsPlaceMetadataLookup(RobloxExperiencePresencePhase phase,
                              int64_t place_id) {
  return (phase == RobloxExperiencePresencePhase::kJoining ||
          phase == RobloxExperiencePresencePhase::kPlaying) &&
         place_id > 0;
}

}  // namespace

void InitializeRobloxHttpClient() {
  std::call_once(g_curl_init_once, InitializeCurl);
}

std::optional<std::string> GetRobloxHttpBody(std::string url) {
  InitializeRobloxHttpClient();
  if (g_curl_init_status != CURLE_OK) {
    return std::nullopt;
  }
  CURL* curl = curl_easy_init();
  if (curl == nullptr) {
    return std::nullopt;
  }
  BoundedResponse response;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3500L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mocktail/0.1");
  curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "X25519:P-256:P-384");
  curl_easy_setopt(curl, CURLOPT_DOH_URL, "https://1.1.1.1/dns-query");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteHttpResponse);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  std::string proxy_url;
  const auto proxy = ReadNetworkProxy(ProcessEnvironment());
  if (proxy.has_value()) {
    proxy_url = BuildNetworkProxyUrl(*proxy);
    curl_easy_setopt(curl, CURLOPT_PROXY, proxy_url.c_str());
    if (!proxy->username.empty()) {
      curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, proxy->username.c_str());
      curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, proxy->password.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "");
  }
  if (const char* ca_bundle = std::getenv("MOCKTAIL_CA_BUNDLE")) {
    curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
  }
  const CURLcode status = curl_easy_perform(curl);
  long http_status = 0;
  if (status == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
  }
  curl_easy_cleanup(curl);
  if (status != CURLE_OK || http_status != 200 || response.exceeded) {
    return std::nullopt;
  }
  return std::move(response.body);
}

ResolvedPlaceMetadata ResolveRobloxPlaceMetadata(int64_t place_id,
                                                 bool fetch_icon) {
  ResolvedPlaceMetadata metadata;
  if (place_id <= 0) {
    return metadata;
  }
  const std::optional<std::string> universe = GetRobloxHttpBody(
      "https://apis.roblox.com/universes/v1/places/" +
      std::to_string(place_id) + "/universe");
  int64_t universe_id = 0;
  if (!universe.has_value() ||
      mocktail_rust_discord_parse_universe_id(universe->data(), universe->size(),
                                              &universe_id) != 0 ||
      universe_id <= 0) {
    return metadata;
  }
  const std::optional<std::string> game = GetRobloxHttpBody(
      "https://games.roblox.com/v1/games?universeIds=" +
      std::to_string(universe_id));
  if (game.has_value()) {
    std::array<char, 129> name_buf{};
    if (mocktail_rust_discord_parse_game_name(game->data(), game->size(),
                                            name_buf.data(),
                                            name_buf.size()) == 0) {
      metadata.name = name_buf.data();
    }
  }
  if (!fetch_icon) {
    return metadata;
  }

  const std::optional<std::string> thumbnail = GetRobloxHttpBody(
      "https://thumbnails.roblox.com/v1/games/icons?universeIds=" +
      std::to_string(universe_id) +
      "&returnPolicy=PlaceHolder&size=512x512&format=Png&isCircular=false");
  if (thumbnail.has_value()) {
    std::array<char, 513> url_buf{};
    if (mocktail_rust_discord_parse_icon_url(thumbnail->data(),
                                           thumbnail->size(), url_buf.data(),
                                           url_buf.size()) == 0) {
      metadata.icon_url = url_buf.data();
    }
  }
  return metadata;
}

std::chrono::seconds RobloxPlaceMetadataRetryDelay(unsigned failures) {
  const unsigned shift = std::min(failures, 5U);
  return std::min(kPlaceMetadataRetryBase * (1U << shift),
                  kPlaceMetadataRetryMaximum);
}

const char* RobloxExperiencePresencePhaseName(
    RobloxExperiencePresencePhase phase) {
  switch (phase) {
    case RobloxExperiencePresencePhase::kBrowsing:
      return "browsing";
    case RobloxExperiencePresencePhase::kJoining:
      return "joining";
    case RobloxExperiencePresencePhase::kPlaying:
      return "playing";
  }
  return "unknown";
}

PlaceMetadataLookupResult RobloxPlaceMetadataCache::Inspect(
    RobloxExperiencePresencePhase phase, int64_t place_id, bool need_icon) {
  PlaceMetadataLookupResult result;
  if (!NeedsPlaceMetadataLookup(phase, place_id)) {
    return result;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const Entry& cached = entries_[place_id];
  result.name = cached.name;
  result.icon_url = cached.icon_url;
  const bool missing_requested =
      cached.name.empty() || (need_icon && cached.icon_url.empty());
  if (missing_requested &&
      std::chrono::steady_clock::now() >= cached.next_attempt) {
    result.should_fetch_after_publish = true;
  }
  result.waiting_for_name = cached.name.empty();
  return result;
}

bool RobloxPlaceMetadataCache::Refresh(
    int64_t place_id, bool fetch_icon,
    std::chrono::seconds* retry_delay_out) {
  if (retry_delay_out != nullptr) {
    *retry_delay_out = std::chrono::seconds{0};
  }
  if (place_id <= 0) {
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    const Entry& existing = entries_[place_id];
    const bool already_complete =
        !existing.name.empty() && (!fetch_icon || !existing.icon_url.empty());
    if (already_complete ||
        std::chrono::steady_clock::now() < existing.next_attempt) {
      return false;
    }
  }

  const ResolvedPlaceMetadata resolved =
      ResolveRobloxPlaceMetadata(place_id, fetch_icon);

  std::lock_guard<std::mutex> lock(mutex_);
  Entry& cached = entries_[place_id];
  bool changed = false;
  if (!resolved.name.empty() && resolved.name != cached.name) {
    cached.name = resolved.name;
    changed = true;
  }
  if (!resolved.icon_url.empty() && resolved.icon_url != cached.icon_url) {
    cached.icon_url = resolved.icon_url;
    changed = true;
  }
  const bool incomplete =
      cached.name.empty() || (fetch_icon && cached.icon_url.empty());
  if (incomplete) {
    const std::chrono::seconds delay =
        RobloxPlaceMetadataRetryDelay(cached.failures++);
    cached.next_attempt = std::chrono::steady_clock::now() + delay;
    if (retry_delay_out != nullptr) {
      *retry_delay_out = delay;
    }
  } else {
    cached.failures = 0;
    cached.next_attempt = {};
  }
  return changed;
}

RobloxPlaceMetadataCache& SharedRobloxPlaceMetadataCache() {
  static auto* cache = new RobloxPlaceMetadataCache();
  return *cache;
}

}  // namespace runtime
}  // namespace mocktail
