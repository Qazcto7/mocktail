#include "update/http_download.h"

#include <string>
#include <string_view>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {
namespace {

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.empty() ? "" : value.data(), value.size()};
}

std::string AssignSlice(MocktailRustStrSlice value) {
  if (value.ptr == nullptr || value.len == 0) {
    return {};
  }
  return std::string(value.ptr, value.len);
}

struct PreparedTransferRequest {
  std::string url;
  std::vector<std::string> headers;
  std::vector<MocktailRustStrSlice> header_slices;
  std::vector<std::string> allowed_hosts;
  std::vector<MocktailRustStrSlice> allowed_host_slices;
  std::string ca_bundle;
  MocktailRustHttpTransferRequestView view{};
};

PreparedTransferRequest BuildTransferRequest(
    const HttpTransferRequest& request) {
  PreparedTransferRequest out;
  out.url = request.url;
  out.headers = request.headers;
  out.allowed_hosts = request.allowed_hosts;
  out.ca_bundle = request.ca_bundle.native();

  out.header_slices.reserve(out.headers.size());
  for (const std::string& header : out.headers) {
    out.header_slices.push_back(ToSlice(header));
  }
  out.allowed_host_slices.reserve(out.allowed_hosts.size());
  for (const std::string& host : out.allowed_hosts) {
    out.allowed_host_slices.push_back(ToSlice(host));
  }

  out.view.url = ToSlice(out.url);
  out.view.headers_ptr =
      out.header_slices.empty() ? nullptr : out.header_slices.data();
  out.view.headers_len = out.header_slices.size();
  out.view.allowed_hosts_ptr = out.allowed_host_slices.empty()
                                   ? nullptr
                                   : out.allowed_host_slices.data();
  out.view.allowed_hosts_len = out.allowed_host_slices.size();
  out.view.ca_bundle = ToSlice(out.ca_bundle);
  out.view.maximum_bytes = request.maximum_bytes;
  out.view.connect_timeout_ms = request.connect_timeout_ms;
  out.view.transfer_timeout_ms = request.transfer_timeout_ms;
  out.view.low_speed_bytes_per_second = request.low_speed_bytes_per_second;
  out.view.low_speed_seconds = request.low_speed_seconds;
  out.view.maximum_attempts = request.maximum_attempts;
  out.view.retry_delay_ms = request.retry_delay_ms;
  out.view.maximum_redirects = request.maximum_redirects;
  return out;
}

}  // namespace

bool IsTrustedHttpsUrl(std::string_view url,
                       const std::vector<std::string>& allowed_hosts,
                       std::string* error) {
  if (error != nullptr) {
    error->clear();
  }
  std::vector<MocktailRustStrSlice> host_slices;
  host_slices.reserve(allowed_hosts.size());
  for (const std::string& host : allowed_hosts) {
    host_slices.push_back(ToSlice(host));
  }
  return mocktail_rust_http_is_trusted_https_url(
      ToSlice(url), host_slices.empty() ? nullptr : host_slices.data(),
      host_slices.size(),
      [](void* ctx, MocktailRustStrSlice err) {
        auto* target = static_cast<std::string*>(ctx);
        if (target != nullptr) {
          *target = AssignSlice(err);
        }
      },
      error);
}

HttpBytesResult DownloadBytes(const HttpTransferRequest& request) {
  const PreparedTransferRequest prepared = BuildTransferRequest(request);
  HttpBytesResult result;
  mocktail_rust_http_download_bytes(
      &prepared.view, nullptr, nullptr,
      [](void* ctx, const MocktailRustHttpBytesResultView* view) {
        auto* out = static_cast<HttpBytesResult*>(ctx);
        if (out == nullptr || view == nullptr) {
          return;
        }
        if (view->bytes_ptr != nullptr && view->bytes_len > 0) {
          out->bytes.assign(reinterpret_cast<const char*>(view->bytes_ptr),
                            view->bytes_len);
        }
        out->status_code = static_cast<long>(view->status_code);
        out->final_url = AssignSlice(view->final_url);
        out->error = AssignSlice(view->error);
      },
      &result);
  return result;
}

HttpDownloadResult DownloadFile(const HttpTransferRequest& request,
                                const std::filesystem::path& destination,
                                int progress_fd) {
  const PreparedTransferRequest prepared = BuildTransferRequest(request);
  const std::string dest_str = destination.native();
  HttpDownloadResult result;
  mocktail_rust_http_download_file(
      &prepared.view, ToSlice(dest_str), progress_fd, nullptr, nullptr,
      [](void* ctx, const MocktailRustHttpDownloadResultView* view) {
        auto* out = static_cast<HttpDownloadResult*>(ctx);
        if (out == nullptr || view == nullptr) {
          return;
        }
        out->bytes_written = view->bytes_written;
        out->sha256 = AssignSlice(view->sha256);
        out->final_url = AssignSlice(view->final_url);
        out->error = AssignSlice(view->error);
      },
      &result);
  return result;
}

}  // namespace mocktail::update
