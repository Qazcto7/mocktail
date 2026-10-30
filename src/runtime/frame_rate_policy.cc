#include "runtime/frame_rate_policy.h"
#include "mocktail/mocktail_rust.h"

#include <array>
#include <cstring>
#include <string>

namespace mocktail {
namespace runtime {
namespace {

FrameRateLimitMode FromRustMode(int mode) {
  switch (mode) {
    case 0: return FrameRateLimitMode::kUnmanaged;
    case 1: return FrameRateLimitMode::kDisplay;
    case 2: return FrameRateLimitMode::kFixed;
    case 3: return FrameRateLimitMode::kUnlimited;
    default: return FrameRateLimitMode::kInvalid;
  }
}

int ToRustMode(FrameRateLimitMode mode) {
  switch (mode) {
    case FrameRateLimitMode::kUnmanaged: return 0;
    case FrameRateLimitMode::kDisplay: return 1;
    case FrameRateLimitMode::kFixed: return 2;
    case FrameRateLimitMode::kUnlimited: return 3;
    case FrameRateLimitMode::kInvalid: return 4;
  }
  return 4;
}

} // namespace

FrameRatePolicy ParseFrameRatePolicy(std::string_view value) {
  const std::string s(value);
  int mode = 0;
  int fps = 0;
  mocktail_rust_frame_rate_parse(s.c_str(), &mode, &fps);
  return {FromRustMode(mode), fps};
}

bool MergeFrameRateClientSettingsOverrides(const FrameRatePolicy &policy,
                                           std::string_view base_json,
                                           std::string *merged_json,
                                           std::string *error) {
  if (merged_json == nullptr || !policy.valid()) {
    if (error != nullptr) {
      *error = "invalid frame-rate policy";
    }
    return false;
  }
  const std::string base_str(base_json);
  std::string out_buf(base_str.size() + 2048, '\0');
  std::array<char, 256> err_buf{};
  int rc = mocktail_rust_frame_rate_merge_client_settings(
      ToRustMode(policy.mode), policy.fixed_fps, base_str.c_str(),
      out_buf.data(), out_buf.size(), err_buf.data(), err_buf.size());
  if (rc == -5) {
    out_buf.resize(out_buf.size() * 2);
    rc = mocktail_rust_frame_rate_merge_client_settings(
        ToRustMode(policy.mode), policy.fixed_fps, base_str.c_str(),
        out_buf.data(), out_buf.size(), err_buf.data(), err_buf.size());
  }
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? err_buf.data() : "cannot merge frame rate overrides";
    }
    return false;
  }
  out_buf.resize(std::strlen(out_buf.data()));
  *merged_json = std::move(out_buf);
  return true;
}

} // namespace runtime
} // namespace mocktail
