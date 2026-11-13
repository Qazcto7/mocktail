#ifndef MOCKTAIL_RUNTIME_ROBLOX_PLACE_METADATA_H_
#define MOCKTAIL_RUNTIME_ROBLOX_PLACE_METADATA_H_

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "runtime/roblox_experience_presence.h"

namespace mocktail {
namespace runtime {

struct ResolvedPlaceMetadata {
  std::string name;
  std::string icon_url;
};

struct PlaceMetadataLookupResult {
  std::string name;
  std::string icon_url;
  bool should_fetch_after_publish = false;
  bool waiting_for_name = false;
};

// Initializes process-wide libcurl state used by Roblox metadata lookups.
void InitializeRobloxHttpClient();

// Performs a bounded HTTPS GET request to Roblox APIs honoring runtime proxy
// and CA bundle settings. Returns std::nullopt on transport or HTTP error.
std::optional<std::string> GetRobloxHttpBody(std::string url);

// Resolves human-readable experience name and (optionally) 512x512 icon URL
// for a Roblox place ID.
ResolvedPlaceMetadata ResolveRobloxPlaceMetadata(int64_t place_id,
                                                 bool fetch_icon = true);

// Computes exponential backoff delay for failed place metadata lookups.
std::chrono::seconds RobloxPlaceMetadataRetryDelay(unsigned failures);

// Returns a stable lowercase phase label for logs ("browsing", "joining",
// "playing").
const char* RobloxExperiencePresencePhaseName(
    RobloxExperiencePresencePhase phase);

// Thread-safe per-place metadata cache shared across RPC integrations so
// concurrent sessions do not duplicate Roblox API lookups.
class RobloxPlaceMetadataCache final {
 public:
  // Checks cached metadata for `place_id` without issuing network I/O.
  PlaceMetadataLookupResult Inspect(RobloxExperiencePresencePhase phase,
                                    int64_t place_id, bool need_icon);

  // Resolves missing metadata over HTTPS and updates cache backoff state.
  // Returns true if cached name or icon URL changed.
  bool Refresh(int64_t place_id, bool fetch_icon,
               std::chrono::seconds* retry_delay_out = nullptr);

 private:
  struct Entry {
    std::string name;
    std::string icon_url;
    std::chrono::steady_clock::time_point next_attempt{};
    unsigned failures = 0;
  };

  std::mutex mutex_;
  std::unordered_map<int64_t, Entry> entries_;
};

// Returns the shared process-wide Roblox place metadata cache.
RobloxPlaceMetadataCache& SharedRobloxPlaceMetadataCache();

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_PLACE_METADATA_H_
