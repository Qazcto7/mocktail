#include "window/roblox_fullscreen_menu_request_gate.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace window {
namespace {

constexpr std::uint64_t kQuietPeriodNs = 20'000'000ULL;
constexpr std::uint64_t kTrailingBurstSuppressionNs = 250'000'000ULL;

}  // namespace

bool RobloxFullscreenMenuRequestGate::RequestFromAndroidLog(
    const char* tag, const char* message, std::uint64_t monotonic_ns) {
  std::lock_guard<std::mutex> lock(mutex_);
  int pending_int = pending_ ? 1 : 0;
  const int res = mocktail_rust_roblox_fullscreen_menu_request(
      tag, message, monotonic_ns, suppress_until_ns_, &last_request_ns_,
      &pending_int);
  if (res != 0) {
    pending_ = (pending_int != 0);
    return true;
  }
  return false;
}

bool RobloxFullscreenMenuRequestGate::Take(std::uint64_t monotonic_ns) {
  std::lock_guard<std::mutex> lock(mutex_);
  int pending_int = pending_ ? 1 : 0;
  const int res = mocktail_rust_roblox_fullscreen_menu_take(
      monotonic_ns, last_request_ns_, kQuietPeriodNs,
      kTrailingBurstSuppressionNs, &suppress_until_ns_, &pending_int);
  if (res != 0) {
    pending_ = (pending_int != 0);
    return true;
  }
  return false;
}

void RobloxFullscreenMenuRequestGate::Reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  last_request_ns_ = 0;
  suppress_until_ns_ = 0;
  pending_ = false;
}

}  // namespace window
}  // namespace mocktail
