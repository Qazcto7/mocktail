#include "runtime/crash_report_policy.h"

#include <string>
#include <string_view>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {

bool MergeCrashReportClientSettingsOverrides(std::string_view base_json,
                                             std::string* merged_json,
                                             std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "crash-report client-settings output is required";
    }
    return false;
  }

  const std::string base_str(base_json);
  std::string out_buf(base_str.size() + 16384, '\0');
  std::size_t out_len = 0;
  int rc = mocktail_rust_merge_crash_report_settings(
      base_str.c_str(), 0, out_buf.data(), out_buf.size(), &out_len);
  if (rc == -5) {
    out_buf.resize(out_buf.size() * 2);
    rc = mocktail_rust_merge_crash_report_settings(
        base_str.c_str(), 0, out_buf.data(), out_buf.size(), &out_len);
  }
  if (rc != 0) {
    if (error != nullptr) {
      *error = "client-settings overrides must be a JSON object";
    }
    return false;
  }
  out_buf.resize(out_len);
  *merged_json = std::move(out_buf);
  return true;
}

bool MergeCrashReportFastFlagsOverrides(std::string_view base_json,
                                        std::string* merged_json,
                                        std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "crash-report fast-flags output is required";
    }
    return false;
  }

  const std::string base_str(base_json);
  std::string out_buf(base_str.size() + 16384, '\0');
  std::size_t out_len = 0;
  int rc = mocktail_rust_merge_crash_report_settings(
      base_str.c_str(), 1, out_buf.data(), out_buf.size(), &out_len);
  if (rc == -5) {
    out_buf.resize(out_buf.size() * 2);
    rc = mocktail_rust_merge_crash_report_settings(
        base_str.c_str(), 1, out_buf.data(), out_buf.size(), &out_len);
  }
  if (rc != 0) {
    if (error != nullptr) {
      *error = "fast-flags overrides must be a JSON object";
    }
    return false;
  }
  out_buf.resize(out_len);
  *merged_json = std::move(out_buf);
  return true;
}

}  // namespace runtime
}  // namespace mocktail
