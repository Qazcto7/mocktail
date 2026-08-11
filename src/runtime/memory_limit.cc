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

#include "runtime/memory_limit.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace mocktail {
namespace runtime {
namespace {

constexpr std::uint64_t kBytesPerKibibyte = 1024U;
constexpr std::uint64_t kBytesPerMebibyte = 1024U * 1024U;
constexpr int kWatchdogPollMilliseconds = 100;
constexpr char kCgroupMarker[] = "MOCKTAIL_MEMORY_CGROUP_LIMIT_BYTES";

void WriteAllBestEffort(int descriptor, std::string_view bytes) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written =
        write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return;
  }
}

bool ParseKibibyteField(std::string_view status, std::string_view field,
                        std::uint64_t* bytes) {
  const std::size_t field_position = status.find(field);
  if (field_position == std::string_view::npos ||
      (field_position != 0 && status[field_position - 1] != '\n')) {
    return false;
  }
  std::size_t value_begin = field_position + field.size();
  while (value_begin < status.size() &&
         (status[value_begin] == ' ' || status[value_begin] == '\t')) {
    ++value_begin;
  }
  std::uint64_t kibibytes = 0;
  const char* begin = status.data() + value_begin;
  const char* end = status.data() + status.size();
  const std::from_chars_result parsed =
      std::from_chars(begin, end, kibibytes);
  if (parsed.ec != std::errc() || parsed.ptr == begin ||
      kibibytes > UINT64_MAX / kBytesPerKibibyte) {
    return false;
  }
  const char* suffix = parsed.ptr;
  while (suffix < end && (*suffix == ' ' || *suffix == '\t')) {
    ++suffix;
  }
  if (end - suffix < 2 || suffix[0] != 'k' || suffix[1] != 'B') {
    return false;
  }
  *bytes = kibibytes * kBytesPerKibibyte;
  return true;
}

ProcessMemoryUsage ReadCurrentProcessMemory() {
  std::array<char, 32768> buffer{};
  const int status_file = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (status_file < 0) {
    return {};
  }
  ssize_t total = 0;
  while (static_cast<std::size_t>(total) < buffer.size()) {
    const ssize_t read_result =
        read(status_file, buffer.data() + total, buffer.size() - total);
    if (read_result > 0) {
      total += read_result;
      continue;
    }
    if (read_result < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  (void)close(status_file);
  if (total <= 0) {
    return {};
  }
  return ParseProcessStatusMemory(
      std::string_view(buffer.data(), static_cast<std::size_t>(total)));
}

bool ReadTextFile(const std::string& path, std::string* value) {
  std::ifstream input(path);
  if (!input) {
    return false;
  }
  return static_cast<bool>(input >> *value);
}

bool ReadUnifiedCgroupPath(std::string* path) {
  std::ifstream input("/proc/self/cgroup");
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("0::", 0) == 0) {
      *path = line.substr(3);
      return !path->empty() && path->front() == '/';
    }
  }
  return false;
}

bool ActiveCgroupMatches(std::uint64_t expected_bytes,
                         std::string* detail) {
  std::string cgroup_path;
  if (!ReadUnifiedCgroupPath(&cgroup_path)) {
    *detail = "cannot resolve the current unified cgroup";
    return false;
  }
  const std::string root = "/sys/fs/cgroup" + cgroup_path;
  std::string memory_max;
  std::string swap_max;
  if (!ReadTextFile(root + "/memory.max", &memory_max) ||
      !ReadTextFile(root + "/memory.swap.max", &swap_max)) {
    *detail = "cannot read current cgroup memory limits";
    return false;
  }
  std::uint64_t configured_bytes = 0;
  const std::from_chars_result parsed = std::from_chars(
      memory_max.data(), memory_max.data() + memory_max.size(),
      configured_bytes);
  if (parsed.ec != std::errc() ||
      parsed.ptr != memory_max.data() + memory_max.size() ||
      configured_bytes > expected_bytes) {
    *detail = "current cgroup memory.max does not match the requested limit";
    return false;
  }
  if (swap_max != "0") {
    *detail = "current cgroup still permits swap";
    return false;
  }
  return true;
}

std::string CurrentExecutable(char* const argv[]) {
  std::array<char, PATH_MAX + 1> executable{};
  const ssize_t length =
      readlink("/proc/self/exe", executable.data(), PATH_MAX);
  if (length > 0) {
    executable[static_cast<std::size_t>(length)] = '\0';
    return executable.data();
  }
  return argv != nullptr && argv[0] != nullptr ? argv[0] : std::string();
}

bool SystemdUserManagerAvailable(std::string* detail) {
  if (access("/sys/fs/cgroup/cgroup.controllers", R_OK) != 0) {
    *detail = "cgroup v2 is not mounted";
    return false;
  }
  if (access("/usr/bin/systemd-run", X_OK) != 0) {
    *detail = "systemd-run is not installed";
    return false;
  }
  const char* runtime_directory = getenv("XDG_RUNTIME_DIR");
  const std::string user_runtime =
      runtime_directory != nullptr && runtime_directory[0] != '\0'
          ? runtime_directory
          : "/run/user/" + std::to_string(geteuid());
  if (access((user_runtime + "/systemd/private").c_str(), F_OK) != 0) {
    *detail = "systemd user manager is not running";
    return false;
  }
  return true;
}

}  // namespace

ProcessMemoryUsage ParseProcessStatusMemory(std::string_view status) {
  ProcessMemoryUsage usage;
  if (!ParseKibibyteField(status, "VmRSS:", &usage.resident_bytes)) {
    return usage;
  }
  std::uint64_t swap_bytes = 0;
  if (status.find("VmSwap:") != std::string_view::npos &&
      !ParseKibibyteField(status, "VmSwap:", &swap_bytes)) {
    return {};
  }
  usage.swap_bytes = swap_bytes;
  usage.valid = usage.resident_bytes <=
                UINT64_MAX - usage.swap_bytes;
  return usage;
}

CgroupMemoryLimitResult MaybeReexecWithCgroupMemoryLimit(
    int argc, char* const argv[], std::uint64_t limit_bytes,
    const std::vector<std::string>* reexec_arguments) {
  CgroupMemoryLimitResult result;
  if (limit_bytes == 0) {
    result.detail = "memory limit is disabled";
    return result;
  }

  const char* marker = getenv(kCgroupMarker);
  if (marker != nullptr) {
    std::uint64_t marked_bytes = 0;
    const std::string_view marker_value(marker);
    const std::from_chars_result parsed = std::from_chars(
        marker_value.data(), marker_value.data() + marker_value.size(),
        marked_bytes);
    if (parsed.ec == std::errc() &&
        parsed.ptr == marker_value.data() + marker_value.size() &&
        marked_bytes == limit_bytes &&
        ActiveCgroupMatches(limit_bytes, &result.detail)) {
      result.status = CgroupMemoryLimitStatus::kActive;
      result.detail = "cgroup v2 MemoryMax is active and swap is disabled";
    } else if (result.detail.empty()) {
      result.detail = "cgroup activation marker is invalid";
    }
    return result;
  }

  if (!SystemdUserManagerAvailable(&result.detail)) {
    return result;
  }
  const std::string executable = CurrentExecutable(argv);
  if (executable.empty()) {
    result.status = CgroupMemoryLimitStatus::kExecFailed;
    result.detail = "cannot resolve the Mocktail executable";
    return result;
  }

  const std::string limit = std::to_string(limit_bytes);
  std::vector<std::string> arguments;
  arguments.reserve((reexec_arguments != nullptr
                         ? reexec_arguments->size()
                         : static_cast<std::size_t>(argc)) +
                    10U);
  arguments.emplace_back("/usr/bin/systemd-run");
  arguments.emplace_back("--user");
  arguments.emplace_back("--scope");
  arguments.emplace_back("--quiet");
  arguments.emplace_back("--same-dir");
  arguments.emplace_back("--expand-environment=no");
  arguments.emplace_back("--property=MemoryMax=" + limit);
  arguments.emplace_back("--property=MemorySwapMax=0");
  arguments.emplace_back("--");
  arguments.push_back(executable);
  if (reexec_arguments != nullptr) {
    arguments.insert(arguments.end(), reexec_arguments->begin(),
                     reexec_arguments->end());
  } else {
    for (int index = 1; index < argc; ++index) {
      arguments.emplace_back(argv[index]);
    }
  }
  std::vector<char*> exec_arguments;
  exec_arguments.reserve(arguments.size() + 1U);
  for (std::string& argument : arguments) {
    exec_arguments.push_back(argument.data());
  }
  exec_arguments.push_back(nullptr);

  if (setenv(kCgroupMarker, limit.c_str(), 1) != 0) {
    result.status = CgroupMemoryLimitStatus::kExecFailed;
    result.detail = std::string("cannot mark cgroup re-exec: ") +
                    std::strerror(errno);
    return result;
  }
  (void)fflush(nullptr);
  execv(arguments.front().c_str(), exec_arguments.data());
  const int exec_error = errno;
  (void)unsetenv(kCgroupMarker);
  result.status = CgroupMemoryLimitStatus::kExecFailed;
  result.detail = std::string("cannot execute systemd-run: ") +
                  std::strerror(exec_error);
  return result;
}

MemoryLimitWatchdog::~MemoryLimitWatchdog() { Stop(); }

bool MemoryLimitWatchdog::Start(std::uint64_t limit_bytes,
                                std::string* error) {
  if (running_ || limit_bytes == 0) {
    if (error != nullptr) {
      *error = running_ ? "memory watchdog is already running"
                        : "memory watchdog requires a non-zero limit";
    }
    return false;
  }
  limit_bytes_ = limit_bytes;
  stop_requested_.store(false, std::memory_order_release);
  const int start_error =
      worker_.Start(&MemoryLimitWatchdog::ThreadEntry, this, 0);
  if (start_error != 0) {
    limit_bytes_ = 0;
    if (error != nullptr) {
      *error = std::string("cannot start memory watchdog: ") +
               std::strerror(start_error);
    }
    return false;
  }
  running_ = true;
  return true;
}

void MemoryLimitWatchdog::Stop() {
  if (!running_) {
    return;
  }
  stop_requested_.store(true, std::memory_order_release);
  const OwnedPthreadWaitResult wait = worker_.WaitFor(-1, 10);
  if (!wait.joined()) {
    std::_Exit(EXIT_FAILURE);
  }
  running_ = false;
  limit_bytes_ = 0;
}

void* MemoryLimitWatchdog::ThreadEntry(void* context) {
  static_cast<MemoryLimitWatchdog*>(context)->Run();
  return nullptr;
}

void MemoryLimitWatchdog::Run() {
  const timespec interval = {
      0, static_cast<long>(kWatchdogPollMilliseconds) * 1000L * 1000L};
  while (!stop_requested_.load(std::memory_order_acquire)) {
    const ProcessMemoryUsage usage = ReadCurrentProcessMemory();
    if (usage.valid && usage.committed_bytes() >= limit_bytes_) {
      const std::uint64_t used_mb =
          usage.committed_bytes() / kBytesPerMebibyte;
      const std::uint64_t limit_mb = limit_bytes_ / kBytesPerMebibyte;
      std::array<char, 256> message{};
      const int length = std::snprintf(
          message.data(), message.size(),
          "[memory] limit exceeded: RSS+swap=%llu MiB, limit=%llu MiB; "
          "terminating Mocktail with exit 137\n",
          static_cast<unsigned long long>(used_mb),
          static_cast<unsigned long long>(limit_mb));
      if (length > 0) {
        const std::size_t write_size =
            std::min(static_cast<std::size_t>(length), message.size() - 1U);
        WriteAllBestEffort(
            STDERR_FILENO,
            std::string_view(message.data(), write_size));
      }
      std::_Exit(137);
    }
    timespec remaining = interval;
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR &&
           !stop_requested_.load(std::memory_order_acquire)) {
    }
  }
}

}  // namespace runtime
}  // namespace mocktail
