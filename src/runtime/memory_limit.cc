#include "runtime/memory_limit.h"
#include "mocktail/mocktail_rust.h"

#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace mocktail {
namespace runtime {
namespace {

constexpr int kHardCapPollMilliseconds = 100;
constexpr int kHardCapPressurePollTicks = 10;    // 10 * 100ms = 1s
constexpr int kAdaptivePollMilliseconds = 250;
constexpr int kAdaptivePressurePollTicks = 4;    // 4 * 250ms = 1s

// Keep the callback registration symbol linked into executables that use the
// watchdog so dynamically loaded stubs can register via dlsym(RTLD_DEFAULT).
volatile const void* g_keep_trim_callback_sym =
    reinterpret_cast<const void*>(&mocktail_rust_memory_register_trim_callback);

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

ProcessMemoryUsage ReadCurrentProcessMemory() {
  ProcessMemoryUsage usage;
  if (mocktail_rust_read_self_memory(&usage.resident_bytes, &usage.swap_bytes) == 1) {
    usage.valid = usage.resident_bytes <= UINT64_MAX - usage.swap_bytes;
    return usage;
  }
  return {};
}

}  // namespace

ProcessMemoryUsage ParseProcessStatusMemory(std::string_view status) {
  ProcessMemoryUsage usage;
  std::string null_status(status);
  if (mocktail_rust_parse_status_memory(null_status.c_str(),
                                        &usage.resident_bytes,
                                        &usage.swap_bytes) == 1) {
    usage.valid = usage.resident_bytes <= UINT64_MAX - usage.swap_bytes;
    return usage;
  }
  return {};
}

CgroupMemoryLimitResult MaybeReexecWithCgroupMemoryLimit(
    int argc, char* const argv[], std::uint64_t limit_bytes,
    const std::vector<std::string>* reexec_arguments) {
  CgroupMemoryLimitResult result;
  (void)argc;
  (void)argv;
  (void)reexec_arguments;
  if (limit_bytes == 0) {
    result.detail = "memory limit is disabled";
    return result;
  }
  result.detail = "automatic cgroup scopes are disabled";
  return result;
}

MemoryLimitWatchdog::~MemoryLimitWatchdog() { Stop(); }

bool MemoryLimitWatchdog::Start(std::uint64_t limit_bytes,
                                std::string* error) {
  return StartInternal(limit_bytes, false, error);
}

bool MemoryLimitWatchdog::StartAdaptiveMonitor(std::string* error) {
  return StartInternal(0, true, error);
}

bool MemoryLimitWatchdog::StartInternal(std::uint64_t limit_bytes,
                                        bool allow_zero_limit,
                                        std::string* error) {
  (void)g_keep_trim_callback_sym;
  if (running_ || (!allow_zero_limit && limit_bytes == 0)) {
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
  const bool enforce_hard_cap = limit_bytes_ > 0;
  const int poll_ms =
      enforce_hard_cap ? kHardCapPollMilliseconds : kAdaptivePollMilliseconds;
  const int pressure_poll_ticks = enforce_hard_cap
                                      ? kHardCapPressurePollTicks
                                      : kAdaptivePressurePollTicks;
  const timespec interval = {0, static_cast<long>(poll_ms) * 1000L * 1000L};
  int ticks = 0;
  while (!stop_requested_.load(std::memory_order_acquire)) {
    if (enforce_hard_cap) {
      const ProcessMemoryUsage usage = ReadCurrentProcessMemory();
      if (usage.valid &&
          mocktail_rust_memory_limit_exceeded(usage.resident_bytes,
                                              usage.swap_bytes, limit_bytes_)) {
        std::array<uint8_t, 256> message{};
        std::size_t out_len = 0;
        if (mocktail_rust_format_memory_limit_message(
                usage.committed_bytes(), limit_bytes_, message.data(),
                message.size(), &out_len) == 0 &&
            out_len > 0) {
          WriteAllBestEffort(
              STDERR_FILENO,
              std::string_view(reinterpret_cast<const char*>(message.data()),
                               out_len));
        }
        std::_Exit(137);
      }
    }

    if ((ticks % pressure_poll_ticks) == 0) {
      (void)mocktail_rust_memory_poll_and_trim(limit_bytes_);
    }
    ++ticks;

    timespec remaining = interval;
    while (nanosleep(&remaining, &remaining) != 0 && errno == EINTR &&
           !stop_requested_.load(std::memory_order_acquire)) {
    }
  }
}

}  // namespace runtime
}  // namespace mocktail
