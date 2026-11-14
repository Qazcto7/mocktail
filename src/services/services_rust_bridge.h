#ifndef MOCKTAIL_SERVICES_SERVICES_RUST_BRIDGE_H_
#define MOCKTAIL_SERVICES_SERVICES_RUST_BRIDGE_H_

#include <cstdint>
#include <string>
#include <string_view>

#include "mocktail/mocktail_rust.h"
#include "services/http_client.h"

namespace mocktail::services::internal {

inline MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.empty() ? "" : value.data(), value.size()};
}

inline std::string AssignSlice(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::string(slice.ptr, slice.len);
}

inline void DispatchInjectedHttpGet(void* http_ctx, MocktailRustStrSlice url,
                                    const MocktailRustStrSlice* headers_ptr,
                                    size_t headers_len, int64_t timeout_ms,
                                    size_t maximum_body_bytes,
                                    bool follow_redirects,
                                    MocktailRustInjectedHttpRespFn on_response,
                                    void* resp_ctx) {
  auto* client = static_cast<HttpClient*>(http_ctx);
  if (client == nullptr || on_response == nullptr) {
    return;
  }
  HttpRequest request;
  request.url = AssignSlice(url);
  request.timeout_ms = static_cast<long>(timeout_ms);
  request.maximum_body_bytes = maximum_body_bytes;
  request.follow_redirects = follow_redirects;
  if (headers_ptr != nullptr && headers_len > 0) {
    request.headers.reserve(headers_len);
    for (size_t i = 0; i < headers_len; ++i) {
      request.headers.push_back(AssignSlice(headers_ptr[i]));
    }
  }
  const HttpResponse resp = client->Get(request);
  on_response(resp_ctx, resp.transport_ok, static_cast<int64_t>(resp.status_code),
              ToSlice(resp.body), ToSlice(resp.error));
}

}  // namespace mocktail::services::internal

#endif  // MOCKTAIL_SERVICES_SERVICES_RUST_BRIDGE_H_
