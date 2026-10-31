#include "runtime/http_client_policy.h"
#include "mocktail/mocktail_rust.h"

#include <string>
#include <string_view>
#include <utility>

namespace mocktail {
namespace runtime {

bool MergeHttpClientSettingsOverrides(std::string_view base_json,
                                      std::string* merged_json,
                                      std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "HttpClient settings output is required";
    }
    return false;
  }

  std::string buf(base_json.size() + 256, '\0');
  size_t out_len = 0;
  const int rc = mocktail_rust_http_client_merge_settings_overrides(
      base_json.data(), base_json.size(), buf.data(), buf.size(), &out_len);
  if (rc != 0) {
    if (error != nullptr) {
      *error = "client-settings overrides must be a JSON object";
    }
    return false;
  }
  buf.resize(out_len);
  *merged_json = std::move(buf);
  return true;
}

}  // namespace runtime
}  // namespace mocktail
