#include "runtime/discord_rpc.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/roblox_place_metadata.h"

namespace mocktail {
namespace runtime {
namespace {

int32_t PhaseToRust(RobloxExperiencePresencePhase phase) {
  switch (phase) {
    case RobloxExperiencePresencePhase::kBrowsing:
      return 0;
    case RobloxExperiencePresencePhase::kJoining:
      return 1;
    case RobloxExperiencePresencePhase::kPlaying:
      return 2;
  }
  return 0;
}

RobloxExperiencePresencePhase PhaseFromRust(int32_t phase_code) {
  switch (phase_code) {
    case 1:
      return RobloxExperiencePresencePhase::kJoining;
    case 2:
      return RobloxExperiencePresencePhase::kPlaying;
    default:
      return RobloxExperiencePresencePhase::kBrowsing;
  }
}

MocktailRustDiscordConfig ToRustConfig(const DiscordRpcConfig& config) {
  MocktailRustDiscordConfig raw{};
  raw.enabled = config.enabled ? 1 : 0;
  raw.show_place_name = config.show_place_name ? 1 : 0;
  raw.show_elapsed_time = config.show_elapsed_time ? 1 : 0;
  raw.join_enabled = config.join_enabled ? 1 : 0;
  raw.public_servers_only = config.public_servers_only ? 1 : 0;
  raw.join_button_label_ptr = config.join_button_label.data();
  raw.join_button_label_len = config.join_button_label.size();
  raw.application_id_ptr = config.application_id.data();
  raw.application_id_len = config.application_id.size();
  raw.text_browsing_ptr = config.text.browsing.data();
  raw.text_browsing_len = config.text.browsing.size();
  raw.text_joining_ptr = config.text.joining.data();
  raw.text_joining_len = config.text.joining.size();
  raw.text_playing_ptr = config.text.playing.data();
  raw.text_playing_len = config.text.playing.size();
  raw.text_state_ptr = config.text.state.data();
  raw.text_state_len = config.text.state.size();
  raw.text_unknown_place_ptr = config.text.unknown_place.data();
  raw.text_unknown_place_len = config.text.unknown_place.size();
  return raw;
}

MocktailRustDiscordLaunchSlice ToSanitizedRustSlice(
    const RobloxExperienceLaunchRequest* request) {
  MocktailRustDiscordLaunchSlice slice{};
  if (request == nullptr) {
    return slice;
  }
  // Never pass access codes or canonical launch JSON to the Discord worker.
  slice.place_id = request->place_id;
  slice.game_instance_id_ptr = request->game_instance_id.data();
  slice.game_instance_id_len = request->game_instance_id.size();
  slice.has_private_access = !request->reserved_server_access_code.empty() ||
                             !request->access_code.empty() ||
                             !request->link_code.empty();
  return slice;
}

void AssignBuiltActivity(void* ctx, const char* details_ptr, size_t details_len,
                         const char* state_ptr, size_t state_len,
                         bool has_start_timestamp, int64_t start_timestamp,
                         const char* large_image_ptr, size_t large_image_len,
                         const char* large_text_ptr, size_t large_text_len,
                         const char* button_label_ptr, size_t button_label_len,
                         const char* button_url_ptr, size_t button_url_len) {
  auto* activity = static_cast<DiscordRpcActivity*>(ctx);
  if (activity == nullptr) {
    return;
  }
  if (details_ptr != nullptr && details_len > 0) {
    activity->details.assign(details_ptr, details_len);
  }
  if (state_ptr != nullptr && state_len > 0) {
    activity->state.assign(state_ptr, state_len);
  }
  if (has_start_timestamp) {
    activity->start_timestamp = start_timestamp;
  }
  if (large_image_ptr != nullptr && large_image_len > 0) {
    activity->large_image.assign(large_image_ptr, large_image_len);
  }
  if (large_text_ptr != nullptr && large_text_len > 0) {
    activity->large_text.assign(large_text_ptr, large_text_len);
  }
  if (button_label_ptr != nullptr && button_label_len > 0) {
    activity->button_label.assign(button_label_ptr, button_label_len);
  }
  if (button_url_ptr != nullptr && button_url_len > 0) {
    activity->button_url.assign(button_url_ptr, button_url_len);
  }
}

void InspectMetadataBridge(void* /*ctx*/, int32_t phase_code, int64_t place_id,
                           MocktailDiscordMetadataInspectResultFn on_result,
                           void* rust_out) {
  if (on_result == nullptr) {
    return;
  }
  const PlaceMetadataLookupResult metadata =
      SharedRobloxPlaceMetadataCache().Inspect(PhaseFromRust(phase_code),
                                               place_id, /*need_icon=*/true);
  on_result(rust_out, metadata.name.data(), metadata.name.size(),
            metadata.icon_url.data(), metadata.icon_url.size(),
            metadata.should_fetch_after_publish, metadata.waiting_for_name);
}

bool RefreshMetadataBridge(void* /*ctx*/, int64_t place_id,
                           int64_t* out_retry_delay_secs) {
  std::chrono::seconds retry_delay{0};
  const bool changed = SharedRobloxPlaceMetadataCache().Refresh(
      place_id, /*fetch_icon=*/true, &retry_delay);
  if (out_retry_delay_secs != nullptr) {
    *out_retry_delay_secs = retry_delay.count();
  }
  return changed;
}

}  // namespace

bool IsPublicDiscordJoin(const RobloxExperienceLaunchRequest& request) {
  return mocktail_rust_discord_has_join_target(
             request.place_id, request.game_instance_id.data(),
             request.game_instance_id.size()) &&
         request.reserved_server_access_code.empty() &&
         request.access_code.empty() && request.link_code.empty();
}

std::string BuildDiscordJoinUrl(const RobloxExperienceLaunchRequest& request) {
  uint8_t buffer[512];
  std::size_t out_len = 0;
  if (mocktail_rust_discord_build_join_url(
          request.place_id, request.game_instance_id.data(),
          request.game_instance_id.size(), buffer, sizeof(buffer),
          &out_len) == 0 &&
      out_len > 0) {
    return std::string(reinterpret_cast<const char*>(buffer), out_len);
  }
  return {};
}

DiscordRpcActivity BuildDiscordRpcActivity(
    const DiscordRpcConfig& config, RobloxExperiencePresencePhase phase,
    const RobloxExperienceLaunchRequest* request, std::string place_name,
    int64_t session_started_at, std::string place_icon_url) {
  DiscordRpcActivity activity;
  const MocktailRustDiscordConfig rust_cfg = ToRustConfig(config);
  const MocktailRustDiscordLaunchSlice slice = ToSanitizedRustSlice(request);
  (void)mocktail_rust_discord_build_activity(
      &rust_cfg, PhaseToRust(phase), request != nullptr,
      request != nullptr ? &slice : nullptr, place_name.data(),
      place_name.size(), session_started_at, place_icon_url.data(),
      place_icon_url.size(), &AssignBuiltActivity, &activity);
  return activity;
}

class DiscordRpcSession::Impl final {
 public:
  explicit Impl(DiscordRpcConfig config) : config_(std::move(config)) {}

  ~Impl() { Stop(); }

  bool Start(std::string* detail) {
    if (!config_.enabled) {
      if (detail != nullptr) {
        *detail = "disabled by runtime policy";
      }
      return true;
    }
    if (config_.application_id.empty()) {
      if (detail != nullptr) {
        *detail = "no Discord application ID is bundled";
      }
      return false;
    }

    InitializeRobloxHttpClient();

    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) {
      return true;
    }

    const MocktailRustDiscordConfig rust_cfg = ToRustConfig(config_);
    const MocktailRustDiscordMetadataCallbacks metadata_callbacks{
        nullptr, &InspectMetadataBridge, &RefreshMetadataBridge};
    std::array<char, 256> err_buf{};
    MocktailRustDiscordSession* rust_session = nullptr;
    const int32_t rc = mocktail_rust_discord_session_start(
        &rust_cfg, &metadata_callbacks, &rust_session, err_buf.data(),
        err_buf.size());
    if (rc != 0 || rust_session == nullptr) {
      if (detail != nullptr) {
        *detail = err_buf[0] != '\0' ? err_buf.data()
                                     : "could not start Discord RPC session";
      }
      return false;
    }

    rust_session_ = rust_session;
    stopping_ = false;
    started_ = true;
    return true;
  }

  void Stop() {
    MocktailRustDiscordSession* session_to_stop = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!started_ || rust_session_ == nullptr) {
        return;
      }
      stopping_ = true;
      started_ = false;
      session_to_stop = rust_session_;
      rust_session_ = nullptr;
    }
    mocktail_rust_discord_session_stop(session_to_stop);
  }

  void Update(RobloxExperiencePresencePhase phase,
              const RobloxExperienceLaunchRequest* request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!started_ || stopping_ || rust_session_ == nullptr) {
      return;
    }
    const MocktailRustDiscordLaunchSlice slice = ToSanitizedRustSlice(request);
    (void)mocktail_rust_discord_session_update(
        rust_session_, PhaseToRust(phase), request != nullptr,
        request != nullptr ? &slice : nullptr);
  }

 private:
  const DiscordRpcConfig config_;
  std::mutex mutex_;
  MocktailRustDiscordSession* rust_session_ = nullptr;
  bool started_ = false;
  bool stopping_ = false;
};

DiscordRpcSession::DiscordRpcSession(DiscordRpcConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

DiscordRpcSession::~DiscordRpcSession() { Stop(); }

bool DiscordRpcSession::Start(std::string* detail) {
  return impl_->Start(detail);
}

void DiscordRpcSession::Stop() { impl_->Stop(); }

RobloxExperiencePresenceObserver DiscordRpcSession::observer() {
  return {this, &DiscordRpcSession::Notify};
}

void DiscordRpcSession::Notify(void* context,
                               RobloxExperiencePresencePhase phase,
                               const RobloxExperienceLaunchRequest* request) {
  if (context != nullptr) {
    static_cast<DiscordRpcSession*>(context)->impl_->Update(phase, request);
  }
}

}  // namespace runtime
}  // namespace mocktail
