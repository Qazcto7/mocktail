#include "update/http_download.h"

#include <curl/curl.h>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

std::once_flag g_curl_once;
CURLcode g_curl_status = CURLE_FAILED_INIT;

void InitialiseCurl() { g_curl_status = curl_global_init(CURL_GLOBAL_DEFAULT); }

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.data(), value.size()};
}

std::string ToString(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::string(slice.ptr, slice.len);
}

void AssignError(void* ctx, MocktailRustStrSlice error) {
  auto* target = static_cast<std::string*>(ctx);
  if (target != nullptr) {
    *target = ToString(error);
  }
}

struct CurlHandleDeleter {
  void operator()(CURL* handle) const {
    if (handle != nullptr) curl_easy_cleanup(handle);
  }
};

struct CurlHeadersDeleter {
  void operator()(curl_slist* headers) const {
    if (headers != nullptr) curl_slist_free_all(headers);
  }
};

std::unique_ptr<curl_slist, CurlHeadersDeleter> BuildHeaders(
    const MocktailRustStrSlice* ptr, std::size_t len, bool* allocated) {
  *allocated = true;
  if (ptr == nullptr || len == 0) {
    return {};
  }
  curl_slist* list = nullptr;
  for (std::size_t i = 0; i < len; ++i) {
    const std::string value = ToString(ptr[i]);
    curl_slist* next = curl_slist_append(list, value.c_str());
    if (next == nullptr) {
      curl_slist_free_all(list);
      *allocated = false;
      return {};
    }
    list = next;
  }
  return std::unique_ptr<curl_slist, CurlHeadersDeleter>(list);
}

std::string RedirectUrl(CURL* handle) {
  char* value = nullptr;
  if (curl_easy_getinfo(handle, CURLINFO_REDIRECT_URL, &value) != CURLE_OK ||
      value == nullptr) {
    return {};
  }
  return value;
}

std::string CurlFailure(CURLcode status,
                        const std::array<char, CURL_ERROR_SIZE>& buffer) {
  return buffer[0] != '\0' ? std::string(buffer.data())
                           : std::string(curl_easy_strerror(status));
}

std::size_t WriteCurlCallback(char* data, std::size_t size, std::size_t count,
                              void* opaque) {
  const auto* req =
      static_cast<const MocktailRustHttpAttemptRequestView*>(opaque);
  if (req == nullptr || req->on_write == nullptr ||
      (count != 0 && size > std::numeric_limits<std::size_t>::max() / count)) {
    return 0;
  }
  const std::size_t bytes = size * count;
  if (bytes > 0 && data == nullptr) {
    return 0;
  }
  return req->on_write(req->attempt_ctx,
                       reinterpret_cast<const std::uint8_t*>(data), bytes)
             ? bytes
             : 0;
}

std::size_t HeaderCurlCallback(char* data, std::size_t size, std::size_t nitems,
                               void* opaque) {
  const auto* req =
      static_cast<const MocktailRustHttpAttemptRequestView*>(opaque);
  if (req == nullptr || req->on_header == nullptr ||
      (nitems != 0 && size > std::numeric_limits<std::size_t>::max() / nitems)) {
    return 0;
  }
  const std::size_t bytes = size * nitems;
  if (bytes > 0 && data == nullptr) {
    return 0;
  }
  return req->on_header(req->attempt_ctx,
                        reinterpret_cast<const std::uint8_t*>(data), bytes)
             ? bytes
             : 0;
}

int ProgressCurlCallback(void* opaque, curl_off_t expected, curl_off_t now,
                         curl_off_t, curl_off_t) {
  const auto* req =
      static_cast<const MocktailRustHttpAttemptRequestView*>(opaque);
  if (req == nullptr || req->on_progress == nullptr) {
    return 0;
  }
  return req->on_progress(req->attempt_ctx, static_cast<std::int64_t>(expected),
                          static_cast<std::int64_t>(now));
}

bool ConfigureAttempt(CURL* handle, const MocktailRustHttpAttemptRequestView* req,
                      const std::string& url, const std::string& ca_bundle,
                      const std::string& range, curl_slist* headers,
                      std::array<char, CURL_ERROR_SIZE>* error_buffer) {
  if (curl_easy_setopt(handle, CURLOPT_URL, url.c_str()) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_REDIR_PROTOCOLS_STR, "https") !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS,
                       static_cast<long>(req->connect_timeout_ms)) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS,
                       static_cast<long>(req->transfer_timeout_ms)) !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_LOW_SPEED_LIMIT,
                       static_cast<long>(req->low_speed_bytes_per_second)) !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_LOW_SPEED_TIME,
                       static_cast<long>(req->low_speed_seconds)) != CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_ACCEPT_ENCODING,
                       req->accept_encoding_identity ? "identity" : "") !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_SSL_EC_CURVES, "X25519:P-256:P-384") !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_DOH_URL, "https://1.1.1.1/dns-query") !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_USERAGENT, "Mocktail-native-updater/1") !=
          CURLE_OK ||
      curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, error_buffer->data()) !=
          CURLE_OK) {
    return false;
  }
  if (!ca_bundle.empty() &&
      curl_easy_setopt(handle, CURLOPT_CAINFO, ca_bundle.c_str()) != CURLE_OK) {
    return false;
  }
  if (headers != nullptr &&
      curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers) != CURLE_OK) {
    return false;
  }
  if (req->accept_encoding_identity) {
    curl_easy_setopt(handle, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
    if (req->on_header != nullptr) {
      curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, HeaderCurlCallback);
      curl_easy_setopt(handle, CURLOPT_HEADERDATA,
                       const_cast<MocktailRustHttpAttemptRequestView*>(req));
    }
  }
  if (req->on_write != nullptr) {
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, WriteCurlCallback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA,
                     const_cast<MocktailRustHttpAttemptRequestView*>(req));
  }
  curl_easy_setopt(handle, CURLOPT_NOPROGRESS, req->enable_progress ? 0L : 1L);
  if (req->enable_progress && req->on_progress != nullptr) {
    curl_easy_setopt(handle, CURLOPT_XFERINFOFUNCTION, ProgressCurlCallback);
    curl_easy_setopt(handle, CURLOPT_XFERINFODATA,
                     const_cast<MocktailRustHttpAttemptRequestView*>(req));
  }
  if (req->has_resume_offset) {
    curl_easy_setopt(handle, CURLOPT_RANGE, range.c_str());
  }
  return true;
}

void PerformHttpAttempt(
    void* /*transport_ctx*/, const MocktailRustHttpAttemptRequestView* req,
    void (*on_outcome)(void* ctx,
                       const MocktailRustHttpAttemptOutcomeView* outcome),
    void* outcome_ctx) {
  if (on_outcome == nullptr || req == nullptr) {
    return;
  }

  MocktailRustHttpAttemptOutcomeView outcome{};
  std::call_once(g_curl_once, InitialiseCurl);
  if (g_curl_status != CURLE_OK) {
    outcome.init_failed = true;
    const char* err = curl_easy_strerror(g_curl_status);
    outcome.curl_error = ToSlice(err != nullptr ? err : "");
    on_outcome(outcome_ctx, &outcome);
    return;
  }

  std::unique_ptr<CURL, CurlHandleDeleter> handle(curl_easy_init());
  if (!handle) {
    outcome.init_failed = true;
    outcome.curl_error = ToSlice("curl_easy_init failed");
    on_outcome(outcome_ctx, &outcome);
    return;
  }

  bool headers_ok = true;
  auto headers = BuildHeaders(req->headers_ptr, req->headers_len, &headers_ok);
  if (!headers_ok) {
    outcome.headers_alloc_failed = true;
    on_outcome(outcome_ctx, &outcome);
    return;
  }

  const std::string url = ToString(req->url);
  const std::string ca_bundle = ToString(req->ca_bundle);
  const std::string range =
      req->has_resume_offset ? (std::to_string(req->resume_offset) + "-")
                             : std::string();
  std::array<char, CURL_ERROR_SIZE> error_buffer{};
  if (!ConfigureAttempt(handle.get(), req, url, ca_bundle, range, headers.get(),
                        &error_buffer)) {
    outcome.configure_failed = true;
    on_outcome(outcome_ctx, &outcome);
    return;
  }

  const CURLcode status = curl_easy_perform(handle.get());
  long http_status = 0;
  curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &http_status);
  const std::string redirect_url = RedirectUrl(handle.get());
  const std::string curl_error =
      status != CURLE_OK ? CurlFailure(status, error_buffer) : std::string();

  outcome.curl_code = static_cast<std::int32_t>(status);
  outcome.is_range_error = (status == CURLE_RANGE_ERROR);
  outcome.http_status = static_cast<std::int64_t>(http_status);
  outcome.redirect_url = ToSlice(redirect_url);
  outcome.curl_error = ToSlice(curl_error);
  on_outcome(outcome_ctx, &outcome);
}

struct TransferRequestStorage {
  std::vector<MocktailRustStrSlice> headers;
  std::vector<MocktailRustStrSlice> allowed_hosts;
  std::string ca_bundle;
  MocktailRustHttpTransferRequestView view{};
};

void BuildRequestView(const HttpTransferRequest& request,
                      TransferRequestStorage* storage) {
  storage->headers.reserve(request.headers.size());
  for (const std::string& header : request.headers) {
    storage->headers.push_back(ToSlice(header));
  }
  storage->allowed_hosts.reserve(request.allowed_hosts.size());
  for (const std::string& host : request.allowed_hosts) {
    storage->allowed_hosts.push_back(ToSlice(host));
  }
  storage->ca_bundle = request.ca_bundle.string();

  storage->view.url = ToSlice(request.url);
  storage->view.headers_ptr = storage->headers.data();
  storage->view.headers_len = storage->headers.size();
  storage->view.allowed_hosts_ptr = storage->allowed_hosts.data();
  storage->view.allowed_hosts_len = storage->allowed_hosts.size();
  storage->view.ca_bundle = ToSlice(storage->ca_bundle);
  storage->view.maximum_bytes = request.maximum_bytes;
  storage->view.connect_timeout_ms =
      static_cast<std::int64_t>(request.connect_timeout_ms);
  storage->view.transfer_timeout_ms =
      static_cast<std::int64_t>(request.transfer_timeout_ms);
  storage->view.low_speed_bytes_per_second =
      static_cast<std::int64_t>(request.low_speed_bytes_per_second);
  storage->view.low_speed_seconds =
      static_cast<std::int64_t>(request.low_speed_seconds);
  storage->view.maximum_attempts = request.maximum_attempts;
  storage->view.retry_delay_ms =
      static_cast<std::int64_t>(request.retry_delay_ms);
  storage->view.maximum_redirects = request.maximum_redirects;
}

}  // namespace

bool IsTrustedHttpsUrl(std::string_view url,
                       const std::vector<std::string>& allowed_hosts,
                       std::string* error) {
  std::vector<MocktailRustStrSlice> host_slices;
  host_slices.reserve(allowed_hosts.size());
  for (const std::string& host : allowed_hosts) {
    host_slices.push_back(ToSlice(host));
  }
  std::string rust_error;
  const bool ok = mocktail_rust_http_is_trusted_https_url(
      ToSlice(url), host_slices.data(), host_slices.size(), AssignError,
      &rust_error);
  if (!ok && error != nullptr) {
    *error = std::move(rust_error);
  }
  return ok;
}

HttpBytesResult DownloadBytes(const HttpTransferRequest& request) {
  TransferRequestStorage storage;
  BuildRequestView(request, &storage);
  HttpBytesResult result;
  mocktail_rust_http_download_bytes(
      &storage.view, PerformHttpAttempt, nullptr,
      [](void* ctx, const MocktailRustHttpBytesResultView* view) {
        if (ctx == nullptr || view == nullptr) {
          return;
        }
        auto* out = static_cast<HttpBytesResult*>(ctx);
        if (view->bytes_ptr != nullptr && view->bytes_len > 0) {
          out->bytes.assign(reinterpret_cast<const char*>(view->bytes_ptr),
                            view->bytes_len);
        }
        out->status_code = static_cast<long>(view->status_code);
        out->final_url = ToString(view->final_url);
        out->error = ToString(view->error);
      },
      &result);
  return result;
}

HttpDownloadResult DownloadFile(const HttpTransferRequest& request,
                                const std::filesystem::path& destination,
                                int progress_fd) {
  TransferRequestStorage storage;
  BuildRequestView(request, &storage);
  const std::string dest_str = destination.string();
  HttpDownloadResult result;
  mocktail_rust_http_download_file(
      &storage.view, ToSlice(dest_str), progress_fd, PerformHttpAttempt,
      nullptr,
      [](void* ctx, const MocktailRustHttpDownloadResultView* view) {
        if (ctx == nullptr || view == nullptr) {
          return;
        }
        auto* out = static_cast<HttpDownloadResult*>(ctx);
        out->bytes_written = view->bytes_written;
        out->sha256 = ToString(view->sha256);
        out->final_url = ToString(view->final_url);
        out->error = ToString(view->error);
      },
      &result);
  return result;
}

}  // namespace mocktail::update
