#ifndef MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_
#define MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_

#include <chrono>
#include <string>

#include "runtime/environment.h"
#include "runtime/runtime_paths.h"

namespace mocktail {
namespace runtime {

struct PayloadUpdatePreflightResult {
  bool attempted = false;
  std::string error;
  std::string details;

  explicit operator bool() const { return error.empty(); }
};

PayloadUpdatePreflightResult RunPayloadUpdatePreflight(
    const Environment& environment, const RuntimePaths& paths,
    bool force_run_latest = false);

class BackgroundPayloadUpdate final {
 public:
  BackgroundPayloadUpdate() = default;
  ~BackgroundPayloadUpdate();
  BackgroundPayloadUpdate(const BackgroundPayloadUpdate&) = delete;
  BackgroundPayloadUpdate& operator=(const BackgroundPayloadUpdate&) = delete;

  void Start(const Environment& environment, const RuntimePaths& paths,
             std::chrono::milliseconds interval = std::chrono::minutes(30));
  void Stop();

 private:
  void* handle_ = nullptr;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_PAYLOAD_UPDATE_PREFLIGHT_H_
