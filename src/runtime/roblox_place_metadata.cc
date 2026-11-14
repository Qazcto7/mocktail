#include "runtime/roblox_place_metadata.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr std::size_t kMaximumRobloxApiBytes = 512U * 1024U;
constexpr std::chrono::seconds kPlaceMetadataRetryBase{10};
constexpr std::chrono::seconds kPlaceMetadataRetryMaximum{300};

struct HttpBodyCapture {
  std::string body;
  long status_code = 0;
  bool transport_ok = false;
};

bool NeedsPlaceMetadataLookup(RobloxExperiencePresencePhase phase,
                              int64_t place_id) {
  return (phase == RobloxExperiencePresencePhase::kJoining ||
          phase == RobloxExperiencePresencePhase::kPlaying) &&
         place_id > 0;
}

}  // namespace

void InitializeRobloxHttpClient() {
  (void)mocktail_rust_http_transport_init();
}

std::optional<std::string> GetRobloxHttpBody(std::string url) {
  if (mocktail_rust_http_transport_init() != 0 || url.empty()) {
    return std::nullopt;
  }
  static constexpr std::string_view kUserAgentHeader = "User-Agent: Mocktail/0.1";
  const MocktailRustStrSlice ua_slice{kUserAgentHeader.data(),
                                      kUserAgentHeader.size()};

  MocktailRustServiceHttpRequestView view{};
  view.is_post = false;
  view.url = {url.data(), url.size()};
  view.body = {"", 0};
  view.headers_ptr = &ua_slice;
  view.headers_len = 1;
  view.ca_bundle = {"", 0};
  view.timeout_ms = 3500;
  view.max_redirects = 0;
  view.max_response_bytes = kMaximumRobloxApiBytes;
  view.max_attempts = 1;
  view.allow_local_socks5_fallback = false;
  view.fallback_env_ca_bundle = true;
  view.use_runtime_env_proxy = true;

  HttpBodyCapture capture;
  const bool ok = mocktail_rust_services_http_perform(
      &view,
      [](void* ctx, int32_t status_code, const char* body_ptr, size_t body_len,
         const MocktailRustStrSlice* /*headers_ptr*/, size_t /*headers_len*/,
         const char* error_ptr, size_t error_len, bool /*tls_cert_error*/) {
        auto* out = static_cast<HttpBodyCapture*>(ctx);
        out->status_code = static_cast<long>(status_code);
        out->transport_ok = (error_ptr == nullptr || error_len == 0);
        if (body_ptr != nullptr && body_len > 0) {
          out->body.assign(body_ptr, body_len);
        }
      },
      &capture);
  if (!ok || !capture.transport_ok || capture.status_code != 200 ||
      capture.body.size() > kMaximumRobloxApiBytes) {
    return std::nullopt;
  }
  return std::move(capture.body);
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
