#include "runtime/performance_policy.h"
#include "mocktail/mocktail_rust.h"

#include <sched.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include "runtime/crash_report_policy.h"
#include "runtime/http_client_policy.h"
#include "runtime/texture_memory_policy.h"

namespace mocktail {
namespace runtime {
namespace {

bool ReadTopologyValue(int logical_cpu, std::string_view name, int* value) {
  const std::string path = "/sys/devices/system/cpu/cpu" +
                           std::to_string(logical_cpu) + "/topology/" +
                           std::string(name);
  std::ifstream input(path);
  return static_cast<bool>(input >> *value);
}

int LogicalCpuFallback(const cpu_set_t* allowed) {
  int count = 0;
  if (allowed != nullptr) {
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
      if (CPU_ISSET(cpu, allowed)) {
        ++count;
      }
    }
  }
  if (count > 0) {
    return count;
  }
  return static_cast<int>(std::max(1U, std::thread::hardware_concurrency()));
}

}  // namespace

bool ParsePhysicsWorkerMode(std::string_view value, PhysicsWorkerMode* mode) {
  if (mode == nullptr) {
    return false;
  }
  int32_t out_mode = 0;
  if (!mocktail_rust_performance_parse_physics_worker_mode(
          value.data(), value.size(), &out_mode)) {
    return false;
  }
  *mode = static_cast<PhysicsWorkerMode>(out_mode);
  return true;
}

std::string_view PhysicsWorkerModeName(PhysicsWorkerMode mode) {
  return mocktail_rust_performance_physics_worker_mode_name(
      static_cast<int32_t>(mode));
}

int CalculateThroughputWorkerCount(int available_physical_cores) {
  return mocktail_rust_performance_calculate_throughput_worker_count(
      available_physical_cores);
}

PerformancePolicy ParsePerformancePolicy(
    std::string_view multithreaded_rendering, std::string_view memory_limit_mb,
    std::string_view game_mode, std::string_view physics_worker_mode) {
  PerformancePolicy policy;
  policy.multithreaded_rendering = multithreaded_rendering == "1" ||
                                   multithreaded_rendering == "true" ||
                                   multithreaded_rendering == "on";
  policy.physics_worker_mode_valid =
      ParsePhysicsWorkerMode(physics_worker_mode, &policy.physics_worker_mode);
  if (policy.multithreaded_rendering ||
      policy.physics_worker_mode == PhysicsWorkerMode::kThroughput) {
    policy.physical_core_count = DetectAvailablePhysicalCoreCount();
  }
  const char* memory_begin = memory_limit_mb.data();
  const char* memory_end = memory_begin + memory_limit_mb.size();
  const std::from_chars_result memory_parsed =
      std::from_chars(memory_begin, memory_end, policy.memory_limit_mb);
  policy.memory_limit_valid =
      memory_parsed.ec == std::errc() && memory_parsed.ptr == memory_end &&
      policy.memory_limit_mb <=
          std::numeric_limits<std::uint64_t>::max() / (1024U * 1024U);
  policy.game_mode_valid = ParseGameModePolicy(game_mode, &policy.game_mode);
  return policy;
}

int DetectAvailablePhysicalCoreCount() {
  cpu_set_t allowed;
  CPU_ZERO(&allowed);
  if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
    return LogicalCpuFallback(nullptr);
  }

  std::set<std::pair<int, int>> physical_cores;
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (!CPU_ISSET(cpu, &allowed)) {
      continue;
    }
    int package_id = 0;
    int core_id = 0;
    if (!ReadTopologyValue(cpu, "physical_package_id", &package_id) ||
        !ReadTopologyValue(cpu, "core_id", &core_id)) {
      return LogicalCpuFallback(&allowed);
    }
    physical_cores.emplace(package_id, core_id);
  }
  return physical_cores.empty() ? LogicalCpuFallback(&allowed)
                                : static_cast<int>(physical_cores.size());
}

bool MergePerformanceClientSettingsOverrides(const PerformancePolicy& policy,
                                             std::string_view base_json,
                                             std::string* merged_json,
                                             std::string* error) {
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "performance client-settings output is required";
    }
    return false;
  }
  const bool throughput_mode =
      policy.physics_worker_mode == PhysicsWorkerMode::kThroughput;
  const bool latency_mode =
      policy.physics_worker_mode == PhysicsWorkerMode::kLatency;
  int available_workers = 0;
  if (throughput_mode || (policy.multithreaded_rendering && !latency_mode)) {
    available_workers = policy.physical_core_count > 0
                            ? policy.physical_core_count
                            : DetectAvailablePhysicalCoreCount();
  }
  const char* custom_quality = nullptr;
  std::size_t custom_quality_len = 0;
  if ((policy.multithreaded_rendering || throughput_mode) && !latency_mode) {
    custom_quality = std::getenv("MOCKTAIL_GRAPHICS_QUALITY");
    if (custom_quality != nullptr) {
      custom_quality_len = std::strlen(custom_quality);
    }
  }
  std::array<char, 256> err_buf{};
  std::string output;
  const int32_t rc = mocktail_rust_performance_merge_overrides(
      policy.multithreaded_rendering,
      static_cast<int32_t>(policy.physics_worker_mode),
      policy.physics_worker_mode_valid, available_workers, custom_quality,
      custom_quality_len, base_json.data(), base_json.size(),
      [](void* ctx, const char* ptr, std::size_t len) {
        static_cast<std::string*>(ctx)->assign(ptr, len);
      },
      &output, err_buf.data(), err_buf.size());
  if (rc != 0) {
    if (error != nullptr) {
      *error = err_buf[0] != '\0' ? std::string(err_buf.data())
                                  : "performance client-settings merge failed";
    }
    return false;
  }
  *merged_json = std::move(output);
  return true;
}

bool MergeRuntimeClientSettingsOverrides(const FrameRatePolicy& frame_rate,
                                         const PerformancePolicy& performance,
                                         std::string_view base_json,
                                         std::string* merged_json,
                                         std::string* error) {
  std::string frame_rate_overrides;
  if (!MergeFrameRateClientSettingsOverrides(frame_rate, base_json,
                                             &frame_rate_overrides, error)) {
    return false;
  }
  std::string performance_overrides;
  if (!MergePerformanceClientSettingsOverrides(
          performance, frame_rate_overrides, &performance_overrides, error)) {
    return false;
  }
  std::string http_client_overrides;
  if (!MergeHttpClientSettingsOverrides(performance_overrides,
                                        &http_client_overrides, error)) {
    return false;
  }
  std::string texture_memory_overrides;
  if (!MergeTextureMemoryClientSettingsOverrides(
          CalculateTextureMemoryBudgetBytes(DetectHostMemoryBytes()),
          http_client_overrides, &texture_memory_overrides, error)) {
    return false;
  }
  return MergeCrashReportClientSettingsOverrides(texture_memory_overrides,
                                                 merged_json, error);
}

bool MergeAudioDeviceMenuClientSettingsOverrides(std::string_view base_json,
                                                 std::string* merged_json,
                                                 std::string* error) {
  if (merged_json == nullptr) {
    return false;
  }
  std::string buf(base_json.size() + 256, '\0');
  size_t out_len = 0;
  const int rc = mocktail_rust_audio_device_menu_merge_overrides(
      base_json.data(), base_json.size(), buf.data(), buf.size(), &out_len);
  if (rc != 0) {
    if (error != nullptr) {
      *error = "audio device menu overrides must be a JSON object";
    }
    return false;
  }
  buf.resize(out_len);
  *merged_json = std::move(buf);
  return true;
}

bool MergeAudioCaptureClientSettingsOverrides(bool microphone_enabled,
                                              std::string_view base_json,
                                              std::string* merged_json,
                                              std::string* error) {
  (void)microphone_enabled;
  if (merged_json == nullptr) {
    if (error != nullptr) {
      *error = "audio capture client-settings output is required";
    }
    return false;
  }
  std::string buf(base_json.size() + 256, '\0');
  size_t out_len = 0;
  const int rc = mocktail_rust_audio_capture_merge_overrides(
      base_json.data(), base_json.size(), buf.data(), buf.size(), &out_len);
  if (rc != 0) {
    if (error != nullptr) {
      *error = "audio capture client-settings input must be a JSON object";
    }
    return false;
  }
  buf.resize(out_len);
  *merged_json = std::move(buf);
  return true;
}

}  // namespace runtime
}  // namespace mocktail
