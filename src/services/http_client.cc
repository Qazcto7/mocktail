#include "services/http_client.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "services_rust_bridge.h"

namespace mocktail {
namespace services {
namespace {

using internal::ToSlice;

HttpResponse PerformRequest(const HttpRequest& request, bool is_post,
                            std::string_view post_body) {
  std::vector<MocktailRustStrSlice> header_slices;
  header_slices.reserve(request.headers.size());
  for (const auto& h : request.headers) {
    header_slices.push_back(ToSlice(h));
  }

  MocktailRustServiceHttpRequestView view{};
  view.is_post = is_post;
  view.url = ToSlice(request.url);
  view.body = is_post ? ToSlice(post_body) : MocktailRustStrSlice{"", 0};
  view.headers_ptr = header_slices.empty() ? nullptr : header_slices.data();
  view.headers_len = header_slices.size();
  view.ca_bundle = MocktailRustStrSlice{"", 0};
  view.timeout_ms = request.timeout_ms;
  view.max_redirects = request.follow_redirects ? 5 : 0;
  view.max_response_bytes = request.maximum_body_bytes;
  view.max_attempts = 3;
  view.allow_local_socks5_fallback = true;
  view.fallback_env_ca_bundle = true;
  view.use_runtime_env_proxy = true;

  HttpResponse response;
  const bool ok = mocktail_rust_services_http_perform(
      &view,
      [](void* ctx, int32_t status_code, const char* body_ptr, size_t body_len,
         const MocktailRustStrSlice* headers_ptr, size_t headers_len,
         const char* error_ptr, size_t error_len, bool /*tls_cert_error*/) {
        auto* out = static_cast<HttpResponse*>(ctx);
        out->status_code = static_cast<long>(status_code);
        if (body_ptr != nullptr && body_len > 0) {
          out->body.assign(body_ptr, body_len);
        }
        if (headers_ptr != nullptr && headers_len > 0) {
          out->headers.reserve(headers_len);
          for (size_t i = 0; i < headers_len; ++i) {
            if (headers_ptr[i].ptr != nullptr && headers_ptr[i].len > 0) {
              out->headers.emplace_back(headers_ptr[i].ptr, headers_ptr[i].len);
            }
          }
        }
        if (error_ptr != nullptr && error_len > 0) {
          out->error.assign(error_ptr, error_len);
        }
      },
      &response);
  response.transport_ok = ok && response.error.empty();
  return response;
}

}  // namespace

HttpResponse CurlHttpClient::Get(const HttpRequest& request) {
  return PerformRequest(request, false, {});
}

HttpResponse CurlHttpClient::Post(const HttpRequest& request,
                                  const std::string& body) {
  return PerformRequest(request, true, body);
}

}  // namespace services
}  // namespace mocktail
