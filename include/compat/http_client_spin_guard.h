#ifndef MOCKTAIL_COMPAT_HTTP_CLIENT_SPIN_GUARD_H_
#define MOCKTAIL_COMPAT_HTTP_CLIENT_SPIN_GUARD_H_

#include <cstdint>

namespace mocktail {
namespace compat {

constexpr std::uint32_t kHttpClientSpinBatchSize = 256;
constexpr std::uint64_t kHttpClientSpinBatchIntervalNs = 1000000;

enum class HttpClientThreadState : std::uint8_t {
  kUnchecked = 0,
  kNotHttpClient = 1,
  kIsHttpClient = 2,
};

// Trivial zero-initialized TLS flag inlined into callers so hot mutex unlocks
// on non-HttpClient threads return immediately without crossing into a slow TU.
inline thread_local std::uint8_t t_http_client_spin_checked_state = 0;

// Pure rate-limiter state used by the process-local HttpClient guard. A normal
// request that does not complete a full mutex batch is never delayed.
class HttpClientSpinRateLimiter {
 public:
  std::uint64_t Observe(std::uint64_t now_ns);

 private:
  std::uint32_t operation_count_ = 0;
  std::uint64_t checkpoint_ns_ = 0;
};

// Called after a successful Bionic mutex unlock. Only a thread named exactly
// "HttpClient" is rate-limited, and only when it completes mutex batches
// faster than the cooperative one-millisecond interval.
void ApplyHttpClientSpinGuard();

inline void ApplyHttpClientSpinGuardFast() {
  if (__builtin_expect(
          t_http_client_spin_checked_state ==
              static_cast<std::uint8_t>(HttpClientThreadState::kNotHttpClient),
          1)) {
    return;
  }
  ApplyHttpClientSpinGuard();
}

}  // namespace compat
}  // namespace mocktail

#endif  // MOCKTAIL_COMPAT_HTTP_CLIENT_SPIN_GUARD_H_
