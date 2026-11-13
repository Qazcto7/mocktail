#include "runtime/micup_rpc.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/environment.h"
#include "runtime/owned_pthread.h"
#include "runtime/roblox_place_metadata.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr std::size_t kMetadataWorkerStackBytes = 8U * 1024U * 1024U;

int32_t PhaseToRustCode(RobloxExperiencePresencePhase phase) {
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

int64_t NowEpochMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace

class MicupRpcSession::Impl final {
 public:
  explicit Impl(MicupRpcConfig config) : config_(std::move(config)) {}

  ~Impl() {
    Stop();
    ZeroSensitiveConfig();
  }

  bool Start(std::string* detail) {
    if (!config_.enabled) {
      if (detail != nullptr) {
        *detail = "disabled by runtime policy";
      }
      return true;
    }

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (started_) {
        return true;
      }
    }

    const std::optional<NetworkProxyConfig> proxy =
        ReadNetworkProxy(ProcessEnvironment());
    std::string proxy_url;
    std::string proxy_user;
    std::string proxy_pass;
    if (proxy.has_value()) {
      proxy_url = BuildNetworkProxyUrl(*proxy, /*include_credentials=*/false);
      proxy_user = proxy->username;
      proxy_pass = proxy->password;
    }
    const char* ca_bundle = std::getenv("MOCKTAIL_CA_BUNDLE");
    std::string ca_bundle_str = ca_bundle != nullptr ? ca_bundle : "";

    MocktailRustMicupConfig rust_cfg{};
    rust_cfg.gateway_url_ptr = config_.gateway_url.data();
    rust_cfg.gateway_url_len = config_.gateway_url.size();
    rust_cfg.token_ptr = config_.token.data();
    rust_cfg.token_len = config_.token.size();
    rust_cfg.token_file_ptr = config_.token_file.data();
    rust_cfg.token_file_len = config_.token_file.size();
    rust_cfg.status_ptr = config_.status.data();
    rust_cfg.status_len = config_.status.size();
    rust_cfg.activity_mode_ptr = config_.activity_mode.data();
    rust_cfg.activity_mode_len = config_.activity_mode.size();
    rust_cfg.text_browsing_ptr = config_.text.browsing.data();
    rust_cfg.text_browsing_len = config_.text.browsing.size();
    rust_cfg.text_joining_ptr = config_.text.joining.data();
    rust_cfg.text_joining_len = config_.text.joining.size();
    rust_cfg.text_playing_ptr = config_.text.playing.data();
    rust_cfg.text_playing_len = config_.text.playing.size();
    rust_cfg.text_unknown_place_ptr = config_.text.unknown_place.data();
    rust_cfg.text_unknown_place_len = config_.text.unknown_place.size();
    rust_cfg.ca_bundle_ptr = ca_bundle_str.data();
    rust_cfg.ca_bundle_len = ca_bundle_str.size();
    rust_cfg.proxy_url_ptr = proxy_url.data();
    rust_cfg.proxy_url_len = proxy_url.size();
    rust_cfg.proxy_username_ptr = proxy_user.data();
    rust_cfg.proxy_username_len = proxy_user.size();
    rust_cfg.proxy_password_ptr = proxy_pass.data();
    rust_cfg.proxy_password_len = proxy_pass.size();
    rust_cfg.enabled = 1;
    rust_cfg.show_place_name = config_.show_place_name ? 1 : 0;
    rust_cfg.show_elapsed_time = config_.show_elapsed_time ? 1 : 0;

    std::array<char, 256> err_buf{};
    MocktailRustMicupSession* rust_session = nullptr;
    const int32_t rc = mocktail_rust_micup_session_start(
        &rust_cfg, &rust_session, err_buf.data(), err_buf.size());

    if (!proxy_pass.empty()) {
      mocktail_rust_secure_zero(reinterpret_cast<uint8_t*>(proxy_pass.data()),
                                proxy_pass.size());
      proxy_pass.clear();
    }

    if (rc != 0 || rust_session == nullptr) {
      if (detail != nullptr) {
        *detail = err_buf[0] != '\0' ? err_buf.data()
                                     : "could not start Micup RPC session";
      }
      return false;
    }

    InitializeRobloxHttpClient();

    {
      std::lock_guard<std::mutex> lock(mutex_);
      rust_session_ = rust_session;
      phase_ = RobloxExperiencePresencePhase::kBrowsing;
      place_id_ = 0;
      session_started_at_ms_ = 0;
      revision_ = 1;
      metadata_pending_ = false;
      stopping_ = false;
      started_ = true;
    }

    if (NeedsPlaceMetadataResolver()) {
      const int err = metadata_worker_.Start(&Impl::RunMetadataWorker, this,
                                             kMetadataWorkerStackBytes);
      if (err != 0) {
        std::fprintf(stderr,
                     "  [micup-rpc] warning: metadata resolver unavailable "
                     "(errno=%d); continuing without experience titles\n",
                     err);
      }
    }

    (void)mocktail_rust_micup_session_update(rust_session_, 0, 0, "", 0, 0, 1);
    return true;
  }

  void Stop() {
    MocktailRustMicupSession* rust_session = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!started_ && !metadata_worker_.joinable()) {
        return;
      }
      stopping_ = true;
      rust_session = rust_session_;
      rust_session_ = nullptr;
      condition_.notify_all();
    }
    if (metadata_worker_.joinable()) {
      (void)metadata_worker_.WaitFor(-1, 1);
    }
    if (rust_session != nullptr) {
      mocktail_rust_micup_session_stop(rust_session);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    started_ = false;
  }

  void Update(RobloxExperiencePresencePhase phase,
              const RobloxExperienceLaunchRequest* request) {
    int64_t place_id = 0;
    if (request != nullptr) {
      // Never copy access codes or private invite secrets.
      place_id = request->place_id;
    }

    MocktailRustMicupSession* rust_session = nullptr;
    uint64_t revision = 0;
    int64_t started_at_ms = 0;
    std::string immediate_place_name;
    bool push_immediately = false;

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!started_ || stopping_ || rust_session_ == nullptr) {
        return;
      }
      phase_ = phase;
      place_id_ = place_id;
      session_started_at_ms_ =
          phase == RobloxExperiencePresencePhase::kPlaying ? NowEpochMs() : 0;
      started_at_ms = session_started_at_ms_;
      revision = ++revision_;
      rust_session = rust_session_;

      const bool wants_place_name =
          (phase == RobloxExperiencePresencePhase::kJoining ||
           phase == RobloxExperiencePresencePhase::kPlaying) &&
          place_id > 0 && config_.show_place_name &&
          config_.activity_mode != "catalog";

      if (!wants_place_name) {
        metadata_pending_ = false;
        push_immediately = true;
      } else {
        const PlaceMetadataLookupResult cached =
            SharedRobloxPlaceMetadataCache().Inspect(phase, place_id,
                                                     /*need_icon=*/false);
        if (!cached.waiting_for_name) {
          immediate_place_name = cached.name;
          metadata_pending_ = cached.should_fetch_after_publish;
          push_immediately = true;
        } else if (metadata_worker_.joinable()) {
          metadata_pending_ = true;
          push_immediately = false;
        } else {
          metadata_pending_ = false;
          push_immediately = true;
        }
      }

      std::fprintf(stderr,
                   "  [micup-rpc] queued phase=%s revision=%llu "
                   "place_id=%lld\n",
                   RobloxExperiencePresencePhaseName(phase_),
                   static_cast<unsigned long long>(revision_),
                   static_cast<long long>(place_id_));
      condition_.notify_all();
    }

    if (push_immediately && rust_session != nullptr) {
      (void)mocktail_rust_micup_session_update(
          rust_session, PhaseToRustCode(phase), place_id,
          immediate_place_name.data(), immediate_place_name.size(),
          started_at_ms, revision);
    }
  }

 private:
  bool NeedsPlaceMetadataResolver() const {
    return config_.show_place_name && config_.activity_mode != "catalog";
  }

  void ZeroSensitiveConfig() {
    if (!config_.token.empty()) {
      mocktail_rust_secure_zero(reinterpret_cast<uint8_t*>(config_.token.data()),
                                config_.token.size());
      config_.token.clear();
    }
  }

  static void* RunMetadataWorker(void* context) {
    static_cast<Impl*>(context)->RunMetadataLoop();
    return nullptr;
  }

  void RunMetadataLoop() {
    auto next_retry_wait = std::chrono::steady_clock::time_point{};
    while (true) {
      RobloxExperiencePresencePhase phase =
          RobloxExperiencePresencePhase::kBrowsing;
      int64_t place_id = 0;
      int64_t started_at_ms = 0;
      uint64_t snapshot_revision = 0;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() {
          return stopping_ || metadata_pending_;
        });
        if (stopping_) {
          break;
        }
        phase = phase_;
        place_id = place_id_;
        started_at_ms = session_started_at_ms_;
        snapshot_revision = revision_;
      }

      if (next_retry_wait != std::chrono::steady_clock::time_point{} &&
          std::chrono::steady_clock::now() < next_retry_wait) {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait_until(lock, next_retry_wait, [this, snapshot_revision]() {
          return stopping_ || revision_ != snapshot_revision;
        });
        if (stopping_) {
          break;
        }
        if (revision_ != snapshot_revision) {
          next_retry_wait = {};
          continue;
        }
      }

      std::chrono::seconds retry_delay{0};
      (void)SharedRobloxPlaceMetadataCache().Refresh(
          place_id, /*fetch_icon=*/false, &retry_delay);
      const PlaceMetadataLookupResult latest =
          SharedRobloxPlaceMetadataCache().Inspect(phase, place_id,
                                                   /*need_icon=*/false);

      MocktailRustMicupSession* rust_session = nullptr;
      uint64_t publish_revision = 0;

      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
          break;
        }
        if (revision_ != snapshot_revision) {
          next_retry_wait = {};
          continue;
        }
        if (!latest.name.empty()) {
          metadata_pending_ = false;
          next_retry_wait = {};
        } else {
          // Publish fallback activity immediately after a lookup miss, then
          // back off cleanly until retry_delay expires.
          if (retry_delay.count() > 0) {
            next_retry_wait = std::chrono::steady_clock::now() + retry_delay;
            metadata_pending_ = true;
          } else {
            next_retry_wait = {};
            metadata_pending_ = false;
          }
        }
        if (rust_session_ != nullptr) {
          rust_session = rust_session_;
          publish_revision = ++revision_;
        }
      }

      if (rust_session != nullptr) {
        (void)mocktail_rust_micup_session_update(
            rust_session, PhaseToRustCode(phase), place_id,
            latest.name.data(), latest.name.size(), started_at_ms,
            publish_revision);
      }
    }
  }

  MicupRpcConfig config_;
  std::mutex mutex_;
  std::condition_variable condition_;
  OwnedPthread metadata_worker_;
  MocktailRustMicupSession* rust_session_ = nullptr;
  RobloxExperiencePresencePhase phase_ =
      RobloxExperiencePresencePhase::kBrowsing;
  int64_t place_id_ = 0;
  int64_t session_started_at_ms_ = 0;
  uint64_t revision_ = 0;
  bool metadata_pending_ = false;
  bool started_ = false;
  bool stopping_ = false;
};

MicupRpcSession::MicupRpcSession(MicupRpcConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

MicupRpcSession::~MicupRpcSession() { Stop(); }

bool MicupRpcSession::Start(std::string* detail) {
  return impl_->Start(detail);
}

void MicupRpcSession::Stop() { impl_->Stop(); }

RobloxExperiencePresenceObserver MicupRpcSession::observer() {
  return {this, &MicupRpcSession::Notify};
}

void MicupRpcSession::Notify(void* context, RobloxExperiencePresencePhase phase,
                             const RobloxExperienceLaunchRequest* request) {
  if (context != nullptr) {
    static_cast<MicupRpcSession*>(context)->impl_->Update(phase, request);
  }
}

}  // namespace runtime
}  // namespace mocktail
