#include "services/browser_tracker_service.h"

#include <string>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace services {
namespace {

struct EnsureContext {
  HttpClient* http_client = nullptr;
  BrowserTrackerResult* result = nullptr;
};

void OnHttpPost(void* raw_ctx, const char* url_ptr, size_t url_len,
                const char* headers_ptr, size_t headers_len,
                const char* body_ptr, size_t body_len, size_t maximum_body_bytes,
                bool* out_transport_ok, int64_t* out_status_code,
                void* receiver_ctx,
                MocktailRustBrowserTrackerHttpResponseReceiver receiver_cb) {
  auto* ctx = static_cast<EnsureContext*>(raw_ctx);
  HttpRequest request;
  request.url.assign(url_ptr, url_len);
  request.maximum_body_bytes = maximum_body_bytes;

  std::size_t start = 0;
  while (start < headers_len) {
    std::size_t end = start;
    while (end < headers_len && headers_ptr[end] != '\n') ++end;
    if (end > start) {
      request.headers.emplace_back(headers_ptr + start, end - start);
    }
    start = end + 1;
  }

  const HttpResponse response = ctx->http_client->Post(
      request, std::string(body_ptr != nullptr ? body_ptr : "", body_len));
  if (out_transport_ok != nullptr) *out_transport_ok = response.transport_ok;
  if (out_status_code != nullptr) *out_status_code = response.status_code;

  if (receiver_cb != nullptr) {
    std::string headers_blob;
    for (const std::string& header : response.headers) {
      headers_blob.append(header);
      headers_blob.push_back('\n');
    }
    receiver_cb(receiver_ctx, response.body.data(), response.body.size(),
                headers_blob.data(), headers_blob.size());
  }
}

void OnResult(void* raw_ctx, int32_t status, int64_t http_status,
              const char* id_ptr, size_t id_len, const char* err_ptr,
              size_t err_len) {
  auto* ctx = static_cast<EnsureContext*>(raw_ctx);
  ctx->result->status = status == 1 ? BrowserTrackerStatus::kCreated
                                    : BrowserTrackerStatus::kExisting;
  ctx->result->http_status = static_cast<long>(http_status);
  ctx->result->browser_tracker_id.assign(id_ptr != nullptr ? id_ptr : "",
                                         id_len);
  ctx->result->error.assign(err_ptr != nullptr ? err_ptr : "", err_len);
}

}  // namespace

BrowserTrackerResult BrowserTrackerService::EnsureInitialized(
    const std::filesystem::path& app_storage_file,
    const std::filesystem::path& cookie_file, bool allow_cookie_update) {
  BrowserTrackerResult result;
  EnsureContext ctx{&http_client_, &result};
  const std::string& storage = app_storage_file.native();
  const std::string& cookies = cookie_file.native();
  mocktail_rust_browser_tracker_ensure_initialized(
      storage.data(), storage.size(), cookies.data(), cookies.size(),
      allow_cookie_update, OnHttpPost, OnResult, &ctx);
  return result;
}

}  // namespace services
}  // namespace mocktail
