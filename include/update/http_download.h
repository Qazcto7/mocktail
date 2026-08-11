// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MOCKTAIL_UPDATE_HTTP_DOWNLOAD_H_
#define MOCKTAIL_UPDATE_HTTP_DOWNLOAD_H_

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace mocktail::update {

struct HttpTransferRequest {
  std::string url;
  std::vector<std::string> headers;
  std::vector<std::string> allowed_hosts;
  std::size_t maximum_bytes = 0;
  long connect_timeout_ms = 10000;
  long transfer_timeout_ms = 120000;
  int maximum_redirects = 5;
};

struct HttpBytesResult {
  std::string bytes;
  long status_code = 0;
  std::string final_url;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

struct HttpDownloadResult {
  std::size_t bytes_written = 0;
  std::string sha256;
  std::string final_url;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

HttpBytesResult DownloadBytes(const HttpTransferRequest& request);

HttpDownloadResult DownloadFile(const HttpTransferRequest& request,
                                const std::filesystem::path& destination,
                                int progress_fd = -1);

bool IsTrustedHttpsUrl(std::string_view url,
                       const std::vector<std::string>& allowed_hosts,
                       std::string* error = nullptr);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_HTTP_DOWNLOAD_H_
