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

#ifndef MOCKTAIL_UPDATE_ZIP_ARCHIVE_H_
#define MOCKTAIL_UPDATE_ZIP_ARCHIVE_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace mocktail::update {

struct ZipEntry {
  std::string name;
  std::uint64_t uncompressed_size = 0;
  bool directory = false;
  bool symbolic_link = false;
};

struct ZipListResult {
  std::vector<ZipEntry> entries;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

struct ZipReadResult {
  std::string bytes;
  std::string error;

  explicit operator bool() const { return error.empty(); }
};

ZipListResult ListZipEntries(const std::filesystem::path& archive,
                             std::size_t maximum_entries = 100000);

ZipReadResult ReadZipEntry(const std::filesystem::path& archive,
                           std::string_view entry, std::size_t maximum_bytes);

bool ExtractZipEntry(const std::filesystem::path& archive,
                     std::string_view entry,
                     const std::filesystem::path& destination,
                     std::size_t maximum_bytes, std::string* error);

bool ExtractZipPrefix(const std::filesystem::path& archive,
                      std::string_view prefix,
                      const std::filesystem::path& destination,
                      std::size_t maximum_total_bytes,
                      std::size_t* extracted_files, std::string* error);

bool IsSafeArchivePath(std::string_view path);

}  // namespace mocktail::update

#endif  // MOCKTAIL_UPDATE_ZIP_ARCHIVE_H_
