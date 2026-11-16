#include "libc_shim/libc_shim.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <limits.h>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <vector>

namespace libc_shim {

namespace {

// Writer serialization for path mapping mutations. Readers use a lock-free
// immutable snapshot guarded by per-thread cache-line-padded reader counters.
std::mutex g_path_mappings_mutex;
std::unordered_map<std::string, std::string> g_path_mappings;
std::vector<std::string> g_ca_bundle_aliases;

struct PathMappingSnapshot {
  struct Bucket {
    std::uint32_t start = 0;
    std::uint32_t count = 0;
    bool has_short_prefix = false;
    std::array<std::uint64_t, 4> bloom256{};
  };

  struct Entry {
    std::uint32_t prefix_offset = 0;
    std::uint32_t prefix_len = 0;
    std::uint32_t host_offset = 0;
    std::uint32_t host_len = 0;
    std::uint8_t first_byte = 0;
  };

  std::array<Bucket, 256> buckets{};
  std::vector<Entry> entries;
  std::string arena;
  bool has_empty_prefix = false;
  std::uint32_t empty_host_offset = 0;
  std::uint32_t empty_host_len = 0;
};

struct alignas(64) ReaderShard {
  std::atomic<std::uint64_t> active{0};
};

constexpr std::size_t kReaderShardCount = 64;
std::array<ReaderShard, kReaderShardCount> g_reader_shards{};
std::atomic<std::uint32_t> g_next_reader_shard{0};
std::atomic<PathMappingSnapshot*> g_path_snapshot{nullptr};

std::uint32_t CurrentReaderShardIndex() noexcept {
  static thread_local const std::uint32_t shard_index =
      g_next_reader_shard.fetch_add(1, std::memory_order_relaxed) &
      static_cast<std::uint32_t>(kReaderShardCount - 1U);
  return shard_index;
}

class SnapshotReadGuard {
 public:
  SnapshotReadGuard() noexcept
      : shard_(&g_reader_shards[CurrentReaderShardIndex()]) {
    shard_->active.fetch_add(1, std::memory_order_seq_cst);
    snapshot_ = g_path_snapshot.load(std::memory_order_seq_cst);
  }

  ~SnapshotReadGuard() {
    shard_->active.fetch_sub(1, std::memory_order_release);
  }

  SnapshotReadGuard(const SnapshotReadGuard&) = delete;
  SnapshotReadGuard& operator=(const SnapshotReadGuard&) = delete;

  const PathMappingSnapshot* get() const noexcept { return snapshot_; }

 private:
  ReaderShard* shard_;
  const PathMappingSnapshot* snapshot_;
};

bool g_installed = false;
std::atomic<GuestAllocator> g_guest_allocator{nullptr};

constexpr char kCaBundleOverride[] = "MOCKTAIL_CA_BUNDLE";
constexpr std::array<const char*, 2> kDefaultCaBundles = {
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
};
constexpr std::array<const char*, 8> kAndroidCaBundlePaths = {
    "/data/user/0/com.roblox.client/files/exe/cacert.pem",
    "/data/data/com.roblox.client/files/exe/cacert.pem",
    "/data/user/0/com.roblox.client/files/exe/ssl/cacert.pem",
    "/data/data/com.roblox.client/files/exe/ssl/cacert.pem",
    "ssl/cacert.pem",
    "content/ssl/cacert.pem",
    "rbx_bin/assets/ssl/cacert.pem",
    "rbx_bin/assets/content/ssl/cacert.pem",
};

bool IsEnabled(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && value[0] != '\0' && value[0] != '0';
}

const char* GetEnvNonEmpty(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && value[0] != '\0' ? value : nullptr;
}

std::string HomePath(const char* suffix) {
  const char* home = std::getenv("HOME");
  return std::string(home && home[0] != '\0' ? home : "/root") +
         (suffix ? suffix : "");
}

std::string RuntimeRoot() {
  const char* runtime_root = std::getenv("MOCKTAIL_RUNTIME_ROOT");
  if (runtime_root != nullptr && runtime_root[0] != '\0') {
    return runtime_root;
  }
  return "runtime/sober";
}

std::string DefaultDataRoot() {
  if (IsEnabled("MOCKTAIL_USE_REAL_SOBER_PATHS")) {
    return HomePath("/.var/app/org.vinegarhq.Sober/data/sober");
  }
  return RuntimeRoot() + "/data";
}

struct PathStats {
  std::atomic<std::uint64_t> calls{0};
  std::atomic<std::uint64_t> fast_skipped{0};
  std::atomic<std::uint64_t> hits{0};
  std::atomic<std::uint64_t> misses{0};
  std::atomic<std::uint64_t> stack_hits{0};
  std::atomic<std::uint64_t> heap_fallbacks{0};
};

PathStats g_path_stats{};

void PrintPathStats() {
  const std::uint64_t calls = g_path_stats.calls.load(std::memory_order_relaxed);
  const std::uint64_t fast_skipped =
      g_path_stats.fast_skipped.load(std::memory_order_relaxed);
  const std::uint64_t hits = g_path_stats.hits.load(std::memory_order_relaxed);
  const std::uint64_t misses =
      g_path_stats.misses.load(std::memory_order_relaxed);
  const std::uint64_t stack_hits =
      g_path_stats.stack_hits.load(std::memory_order_relaxed);
  const std::uint64_t heap_fallbacks =
      g_path_stats.heap_fallbacks.load(std::memory_order_relaxed);
  std::fprintf(stderr,
               "  [libc_shim] path_calls=%llu fast_skipped=%llu hits=%llu "
               "misses=%llu stack=%llu heap=%llu\n",
               static_cast<unsigned long long>(calls),
               static_cast<unsigned long long>(fast_skipped),
               static_cast<unsigned long long>(hits),
               static_cast<unsigned long long>(misses),
               static_cast<unsigned long long>(stack_hits),
               static_cast<unsigned long long>(heap_fallbacks));
}

bool PathStatsEnabled() {
  static const bool enabled =
      IsEnabled("MOCKTAIL_PATH_TRACE_STATS") || IsEnabled("MOCKTAIL_PATH_STATS");
  return enabled;
}

inline std::uint32_t BloomHash256(std::uint8_t b1, std::uint8_t b2) noexcept {
  return ((static_cast<std::uint32_t>(b1) * 131U) ^ b2) & 255U;
}

std::unique_ptr<PathMappingSnapshot> BuildSnapshotLocked() {
  if (g_path_mappings.empty()) {
    return nullptr;
  }
  auto snapshot = std::make_unique<PathMappingSnapshot>();
  std::size_t arena_bytes = 0;
  for (const auto& [android_prefix, host_prefix] : g_path_mappings) {
    arena_bytes += android_prefix.size() + host_prefix.size();
  }
  snapshot->arena.reserve(arena_bytes);
  snapshot->entries.reserve(g_path_mappings.size());

  for (const auto& [android_prefix, host_prefix] : g_path_mappings) {
    const std::uint32_t host_offset =
        static_cast<std::uint32_t>(snapshot->arena.size());
    snapshot->arena.append(host_prefix);
    const std::uint32_t host_len = static_cast<std::uint32_t>(host_prefix.size());

    if (android_prefix.empty()) {
      snapshot->has_empty_prefix = true;
      snapshot->empty_host_offset = host_offset;
      snapshot->empty_host_len = host_len;
      continue;
    }

    const std::uint32_t prefix_offset =
        static_cast<std::uint32_t>(snapshot->arena.size());
    snapshot->arena.append(android_prefix);
    snapshot->entries.push_back(PathMappingSnapshot::Entry{
        prefix_offset,
        static_cast<std::uint32_t>(android_prefix.size()),
        host_offset,
        host_len,
        static_cast<std::uint8_t>(android_prefix[0]),
    });
  }

  // Group entries by first byte and sort longest prefix first within each bucket
  // so the first match found is guaranteed to be the longest matching prefix.
  std::sort(snapshot->entries.begin(), snapshot->entries.end(),
            [](const PathMappingSnapshot::Entry& a,
               const PathMappingSnapshot::Entry& b) {
              if (a.first_byte != b.first_byte) {
                return a.first_byte < b.first_byte;
              }
              if (a.prefix_len != b.prefix_len) {
                return a.prefix_len > b.prefix_len;
              }
              return a.prefix_offset < b.prefix_offset;
            });

  const char* const arena = snapshot->arena.data();
  const std::uint32_t total = static_cast<std::uint32_t>(snapshot->entries.size());
  for (std::uint32_t i = 0; i < total; ++i) {
    const PathMappingSnapshot::Entry& entry = snapshot->entries[i];
    PathMappingSnapshot::Bucket& bucket = snapshot->buckets[entry.first_byte];
    if (bucket.count == 0) {
      bucket.start = i;
    }
    ++bucket.count;
    if (entry.prefix_len < 3U) {
      bucket.has_short_prefix = true;
    } else {
      const std::uint8_t b1 =
          static_cast<std::uint8_t>(arena[entry.prefix_offset + 1]);
      const std::uint8_t b2 =
          static_cast<std::uint8_t>(arena[entry.prefix_offset + 2]);
      const std::uint32_t h = BloomHash256(b1, b2);
      bucket.bloom256[h >> 6] |= (std::uint64_t{1} << (h & 63U));
    }
  }
  return snapshot;
}

void PublishSnapshotLocked() {
  std::unique_ptr<PathMappingSnapshot> next = BuildSnapshotLocked();
  PathMappingSnapshot* old =
      g_path_snapshot.exchange(next.release(), std::memory_order_seq_cst);
  if (old != nullptr) {
    for (ReaderShard& shard : g_reader_shards) {
      int spins = 0;
      while (shard.active.load(std::memory_order_seq_cst) != 0) {
        if (++spins >= 64) {
          std::this_thread::yield();
          spins = 0;
        }
      }
    }
    delete old;
  }
}

struct MatchedPrefix {
  const char* host_prefix = nullptr;
  std::uint32_t host_len = 0;
  std::uint32_t matched_prefix_len = 0;
};

inline MatchedPrefix MatchSnapshot(const PathMappingSnapshot* snap,
                                   const char* path, std::size_t known_len,
                                   bool len_is_known,
                                   std::size_t* out_path_len) noexcept {
  const bool stats = PathStatsEnabled();
  if (stats) {
    g_path_stats.calls.fetch_add(1, std::memory_order_relaxed);
  }
  if (snap == nullptr) {
    if (stats) {
      g_path_stats.fast_skipped.fetch_add(1, std::memory_order_relaxed);
    }
    return {};
  }
  if (path[0] == '\0') {
    if (!snap->has_empty_prefix) {
      if (stats) {
        g_path_stats.fast_skipped.fetch_add(1, std::memory_order_relaxed);
      }
      return {};
    }
    *out_path_len = 0;
    if (stats) {
      g_path_stats.hits.fetch_add(1, std::memory_order_relaxed);
    }
    return {snap->arena.data() + snap->empty_host_offset, snap->empty_host_len,
            0};
  }

  const std::uint8_t c0 = static_cast<std::uint8_t>(path[0]);
  const PathMappingSnapshot::Bucket& bucket = snap->buckets[c0];
  if (bucket.count == 0) {
    if (snap->has_empty_prefix && c0 == '/') {
      *out_path_len = len_is_known ? known_len : std::strlen(path);
      if (stats) {
        g_path_stats.hits.fetch_add(1, std::memory_order_relaxed);
      }
      return {snap->arena.data() + snap->empty_host_offset,
              snap->empty_host_len, 0};
    }
    if (stats) {
      g_path_stats.fast_skipped.fetch_add(1, std::memory_order_relaxed);
    }
    return {};
  }

  if (!bucket.has_short_prefix) {
    const std::uint8_t b1 = static_cast<std::uint8_t>(path[1]);
    const std::uint8_t b2 = b1 != 0 ? static_cast<std::uint8_t>(path[2]) : 0;
    const bool reject =
        (b1 == 0 || b2 == 0) ||
        (((bucket.bloom256[BloomHash256(b1, b2) >> 6] >>
           (BloomHash256(b1, b2) & 63U)) &
          1U) == 0U);
    if (reject) {
      if (snap->has_empty_prefix && c0 == '/') {
        *out_path_len = len_is_known ? known_len : std::strlen(path);
        if (stats) {
          g_path_stats.hits.fetch_add(1, std::memory_order_relaxed);
        }
        return {snap->arena.data() + snap->empty_host_offset,
                snap->empty_host_len, 0};
      }
      if (stats) {
        g_path_stats.fast_skipped.fetch_add(1, std::memory_order_relaxed);
      }
      return {};
    }
  }

  const std::size_t path_len = len_is_known ? known_len : std::strlen(path);
  *out_path_len = path_len;
  const char* const arena = snap->arena.data();
  const PathMappingSnapshot::Entry* const entries =
      snap->entries.data() + bucket.start;
  for (std::uint32_t i = 0; i < bucket.count; ++i) {
    const PathMappingSnapshot::Entry& entry = entries[i];
    if (path_len < entry.prefix_len) {
      continue;
    }
    if (std::memcmp(path, arena + entry.prefix_offset, entry.prefix_len) == 0 &&
        (path_len == entry.prefix_len || path[entry.prefix_len] == '/')) {
      if (stats) {
        g_path_stats.hits.fetch_add(1, std::memory_order_relaxed);
      }
      return {arena + entry.host_offset, entry.host_len, entry.prefix_len};
    }
  }

  if (snap->has_empty_prefix && c0 == '/') {
    if (stats) {
      g_path_stats.hits.fetch_add(1, std::memory_order_relaxed);
    }
    return {snap->arena.data() + snap->empty_host_offset, snap->empty_host_len,
            0};
  }
  if (stats) {
    g_path_stats.misses.fetch_add(1, std::memory_order_relaxed);
  }
  return {};
}

bool ValidateHostCaBundle(const char* path, std::string* canonical_path) {
  if (path == nullptr || path[0] != '/' || canonical_path == nullptr) {
    return false;
  }

  char resolved_path[PATH_MAX];
  if (::realpath(path, resolved_path) == nullptr || resolved_path[0] != '/') {
    return false;
  }

  const int fd = ::open(resolved_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  struct stat file_status {};
  const bool status_available = ::fstat(fd, &file_status) == 0;
  const int close_result = ::close(fd);
  const bool has_read_permission =
      status_available &&
      (file_status.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) != 0;
  if (!status_available || close_result != 0 || !S_ISREG(file_status.st_mode) ||
      file_status.st_size <= 0 || !has_read_permission) {
    return false;
  }

  *canonical_path = resolved_path;
  return true;
}

bool EnsureDirectory(const std::string& path) {
  if (path.empty()) {
    return false;
  }

  std::string partial;
  size_t index = 0;
  if (path[0] == '/') {
    partial = "/";
    index = 1;
  }

  while (index <= path.size()) {
    const size_t next = path.find('/', index);
    std::string component =
        path.substr(index, next == std::string::npos ? next : next - index);
    if (!component.empty()) {
      if (partial.size() > 1 && partial.back() != '/') {
        partial.push_back('/');
      }
      partial += component;
      if (::mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) {
        return false;
      }
    }
    if (next == std::string::npos) {
      break;
    }
    index = next + 1;
  }

  return true;
}

void EnsureDefaultDataLayout(const std::string& data_root) {
  EnsureDirectory(data_root);
  EnsureDirectory(data_root + "/files");
  EnsureDirectory(data_root + "/cache");
  EnsureDirectory(data_root + "/shared_prefs");
  EnsureDirectory(data_root + "/rbx-storage");
  EnsureDirectory(data_root + "/appData");
  EnsureDirectory(data_root + "/appData/LocalStorage");
  EnsureDirectory(data_root + "/appData/rbx-storage");
  EnsureDirectory(data_root + "/files/appData");
  EnsureDirectory(data_root + "/files/appData/LocalStorage");
  EnsureDirectory(data_root + "/files/appData/OTAPatchBackups");
  EnsureDirectory(data_root + "/files/appData/rbx-storage");
  EnsureDirectory(data_root + "/cache/ContentProvider_2");
  EnsureDirectory(data_root + "/cache/rbx-storage");
  EnsureDirectory(data_root + "/cache/sounds");
  EnsureDirectory(data_root + "/sdcard/Android/data/com.roblox.client");
  EnsureDirectory(data_root + "/sdcard/Android/data/com.roblox.client/files");
  EnsureDirectory(data_root + "/sdcard/Android/data/com.roblox.client/cache");
}

}  // namespace

void ConfigureGuestAllocator(GuestAllocator allocator) noexcept {
  g_guest_allocator.store(allocator, std::memory_order_release);
}

GuestAllocator GuestAllocatorForCalls() noexcept {
  return g_guest_allocator.load(std::memory_order_acquire);
}

HostCaBundleResolution ResolveHostCaBundle() {
  const char* override_path = std::getenv(kCaBundleOverride);
  if (override_path != nullptr) {
    HostCaBundleResolution resolution;
    resolution.from_override = true;
    if (!ValidateHostCaBundle(override_path, &resolution.host_path)) {
      resolution.status = HostCaBundleStatus::kInvalidOverride;
      resolution.host_path.clear();
      return resolution;
    }
    resolution.status = HostCaBundleStatus::kReady;
    return resolution;
  }

  for (const char* candidate : kDefaultCaBundles) {
    HostCaBundleResolution resolution;
    if (ValidateHostCaBundle(candidate, &resolution.host_path)) {
      resolution.status = HostCaBundleStatus::kReady;
      return resolution;
    }
  }
  return {};
}

HostCaBundleResolution ConfigureHostCaBundlePathMappings() {
  {
    std::lock_guard<std::mutex> lock(g_path_mappings_mutex);
    for (const auto& alias : g_ca_bundle_aliases) g_path_mappings.erase(alias);
    g_ca_bundle_aliases.assign(kAndroidCaBundlePaths.begin(),
                               kAndroidCaBundlePaths.end());
    if (const char* content = GetEnvNonEmpty("MOCKTAIL_ASSET_PATH")) {
      auto root = std::filesystem::path(content).lexically_normal();
      if (root.filename().empty()) root = root.parent_path();
      g_ca_bundle_aliases.push_back((root / "ssl/cacert.pem").string());
      if (root.filename() == "content")
        g_ca_bundle_aliases.push_back(
            (root.parent_path() / "ssl/cacert.pem").string());
    }
    PublishSnapshotLocked();
  }

  HostCaBundleResolution resolution = ResolveHostCaBundle();
  if (!resolution.ok()) {
    return resolution;
  }
  std::lock_guard<std::mutex> lock(g_path_mappings_mutex);
  for (const auto& alias : g_ca_bundle_aliases)
    g_path_mappings[alias] = resolution.host_path;
  PublishSnapshotLocked();
  return resolution;
}

const char* HostCaBundleStatusName(HostCaBundleStatus status) {
  switch (status) {
    case HostCaBundleStatus::kReady:
      return "Ready";
    case HostCaBundleStatus::kInvalidOverride:
      return "InvalidOverride";
    case HostCaBundleStatus::kUnavailable:
      return "Unavailable";
  }
  return "Unknown";
}

void Install() {
  if (g_installed) {
    return;
  }
  g_installed = true;

  const std::string data_root = DefaultDataRoot();

  RegisterPathMapping("/data/user/0/com.roblox.client", data_root);
  RegisterPathMapping("/data/data/com.roblox.client", data_root);
  const HostCaBundleResolution ca_bundle =
      ConfigureHostCaBundlePathMappings();
  if (ca_bundle.ok()) {
    std::cout << "  [libc_shim] Host CA bundle mapped from "
              << (ca_bundle.from_override ? "validated override"
                                          : "system trust store")
              << '\n';
  } else {
    std::cerr << "  [libc_shim] Host CA bundle unavailable: "
              << HostCaBundleStatusName(ca_bundle.status)
              << "; TLS verification remains fail-closed\n";
  }
  const char* cache_root = GetEnvNonEmpty("MOCKTAIL_ANDROID_CACHE_HOST_ROOT");
  if (cache_root != nullptr) {
    RegisterPathMapping("/data/user/0/com.roblox.client/cache", cache_root);
    RegisterPathMapping("/data/data/com.roblox.client/cache", cache_root);
    EnsureDirectory(cache_root);
  }
  const char* shader_cache_path =
      GetEnvNonEmpty("MOCKTAIL_VULKAN_SHADER_CACHE_HOST_PATH");
  if (shader_cache_path != nullptr) {
    RegisterPathMapping(
        "/data/user/0/com.roblox.client/shadercachevk.bin",
        shader_cache_path);
    RegisterPathMapping(
        "/data/data/com.roblox.client/shadercachevk.bin",
        shader_cache_path);
  }
  const char* asset_content_root = GetEnvNonEmpty("MOCKTAIL_ASSET_PATH");
  if (asset_content_root != nullptr) {
    std::string content_root(asset_content_root);
    while (content_root.size() > 1 && content_root.back() == '/') {
      content_root.pop_back();
    }
    const std::string content_suffix = "/content";
    if (content_root.size() > content_suffix.size() &&
        content_root.compare(content_root.size() - content_suffix.size(),
                             content_suffix.size(), content_suffix) == 0) {
      const std::string assets_root = content_root.substr(
          0, content_root.size() - content_suffix.size());
      RegisterPathMapping("content", content_root);
      RegisterPathMapping("rbx_bin/assets/content", content_root);
      RegisterPathMapping("rbx_bin/assets", assets_root);
    }
  }
  RegisterPathMapping("/sdcard/Android/data/com.roblox.client",
                      data_root + "/sdcard/Android/data/com.roblox.client");
  RegisterPathMapping("/storage/emulated/0/Android/data/com.roblox.client",
                      data_root + "/sdcard/Android/data/com.roblox.client");
  EnsureDefaultDataLayout(data_root);

  std::size_t mapping_count = 0;
  {
    std::lock_guard<std::mutex> lock(g_path_mappings_mutex);
    mapping_count = g_path_mappings.size();
  }
  std::cout << "  [libc_shim] Path shims installed ("
            << mapping_count << " prefix mappings)\n";
}

std::string TranslatePath(const std::string& android_path) {
  SnapshotReadGuard guard;
  std::size_t path_len = 0;
  const MatchedPrefix match = MatchSnapshot(
      guard.get(), android_path.c_str(), android_path.size(), true, &path_len);
  if (match.host_prefix == nullptr) {
    return android_path;
  }
  std::string translated;
  const std::size_t suffix_len = path_len - match.matched_prefix_len;
  translated.reserve(match.host_len + suffix_len);
  translated.append(match.host_prefix, match.host_len);
  translated.append(android_path.data() + match.matched_prefix_len, suffix_len);
  return translated;
}

void RegisterPathMapping(const std::string& android_prefix,
                         const std::string& host_prefix) {
  std::lock_guard<std::mutex> lock(g_path_mappings_mutex);
  g_path_mappings[android_prefix] = host_prefix;
  PublishSnapshotLocked();
}

void ClearPathMappings() {
  std::lock_guard<std::mutex> lock(g_path_mappings_mutex);
  g_path_mappings.clear();
  g_ca_bundle_aliases.clear();
  PublishSnapshotLocked();
}

void DumpPathStats() {
  if (PathStatsEnabled()) {
    PrintPathStats();
  }
}

}  // namespace libc_shim

namespace {

const char* HostPath(const char* path, char* scratch, std::size_t scratch_size,
                     std::string* overflow) {
  if (path == nullptr) {
    return nullptr;
  }
  libc_shim::SnapshotReadGuard guard;
  std::size_t path_len = 0;
  const libc_shim::MatchedPrefix match =
      libc_shim::MatchSnapshot(guard.get(), path, 0, false, &path_len);
  if (match.host_prefix == nullptr) {
    return path;
  }
  const std::size_t suffix_len = path_len - match.matched_prefix_len;
  const std::size_t total_len = match.host_len + suffix_len;
  if (total_len + 1U <= scratch_size) {
    std::memcpy(scratch, match.host_prefix, match.host_len);
    std::memcpy(scratch + match.host_len, path + match.matched_prefix_len,
                suffix_len);
    scratch[total_len] = '\0';
    if (libc_shim::PathStatsEnabled()) {
      libc_shim::g_path_stats.stack_hits.fetch_add(1,
                                                   std::memory_order_relaxed);
    }
    return scratch;
  }
  overflow->resize(total_len);
  std::memcpy(overflow->data(), match.host_prefix, match.host_len);
  std::memcpy(overflow->data() + match.host_len,
              path + match.matched_prefix_len, suffix_len);
  if (libc_shim::PathStatsEnabled()) {
    libc_shim::g_path_stats.heap_fallbacks.fetch_add(
        1, std::memory_order_relaxed);
  }
  return overflow->c_str();
}

bool PathTraceEnabled() {
  static const bool enabled = []() {
    const char* value = std::getenv("MOCKTAIL_PATH_TRACE");
    return value != nullptr && value[0] != '\0' && value[0] != '0';
  }();
  return enabled;
}

void TracePathCall(const char* name, const char* path, const char* host_path,
                   int result) {
  if (!PathTraceEnabled()) {
    return;
  }
  std::fprintf(stderr, "  [path] %s %s", name, path ? path : "(null)");
  if (path != nullptr && host_path != nullptr &&
      std::strcmp(path, host_path) != 0) {
    std::fprintf(stderr, " -> %s", host_path);
  }
  std::fprintf(stderr, " result=%d errno=%d\n", result, result < 0 ? errno : 0);
}

void TracePathCallPtr(const char* name, const char* path,
                      const char* host_path, const void* result) {
  if (!PathTraceEnabled()) {
    return;
  }
  std::fprintf(stderr, "  [path] %s %s", name, path ? path : "(null)");
  if (path != nullptr && host_path != nullptr &&
      std::strcmp(path, host_path) != 0) {
    std::fprintf(stderr, " -> %s", host_path);
  }
  std::fprintf(stderr, " result=%p errno=%d\n", result, result ? 0 : errno);
}

}  // namespace

extern "C" int mocktail_open(const char* path, int flags, ...) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  int result = -1;
  if ((flags & O_CREAT) != 0) {
    va_list args;
    va_start(args, flags);
    mode_t mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
    result = ::open(host_path, flags, mode);
  } else {
    result = ::open(host_path, flags);
  }
  TracePathCall("open", path, host_path, result);
  return result;
}

extern "C" int mocktail___open_2(const char* path, int flags) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  int result = -1;
  if ((flags & O_CREAT) != 0) {
    result = ::open(host_path, flags, 0600);
  } else {
    result = ::open(host_path, flags);
  }
  TracePathCall("__open_2", path, host_path, result);
  return result;
}

extern "C" FILE* mocktail_fopen(const char* path, const char* mode) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  FILE* result = ::fopen(host_path, mode);
  TracePathCallPtr("fopen", path, host_path, result);
  return result;
}

extern "C" int mocktail_access(const char* path, int mode) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  int result = ::access(host_path, mode);
  TracePathCall("access", path, host_path, result);
  return result;
}

extern "C" int mocktail_stat(const char* path, struct stat* statbuf) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  int result = ::stat(host_path, statbuf);
  TracePathCall("stat", path, host_path, result);
  return result;
}

extern "C" int mocktail_lstat(const char* path, struct stat* statbuf) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  int result = ::lstat(host_path, statbuf);
  TracePathCall("lstat", path, host_path, result);
  return result;
}

extern "C" int mocktail_statvfs(const char* path, struct statvfs* statbuf) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::statvfs(HostPath(path, scratch, sizeof(scratch), &overflow),
                   statbuf);
}

extern "C" int mocktail_statfs(const char* path, struct statfs* statbuf) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::statfs(HostPath(path, scratch, sizeof(scratch), &overflow), statbuf);
}

extern "C" int mocktail_mkdir(const char* path, mode_t mode) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::mkdir(HostPath(path, scratch, sizeof(scratch), &overflow), mode);
}

extern "C" DIR* mocktail_opendir(const char* path) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::opendir(HostPath(path, scratch, sizeof(scratch), &overflow));
}

extern "C" int mocktail_rename(const char* old_path, const char* new_path) {
  char scratch_old[PATH_MAX];
  std::string overflow_old;
  char scratch_new[PATH_MAX];
  std::string overflow_new;
  return ::rename(
      HostPath(old_path, scratch_old, sizeof(scratch_old), &overflow_old),
      HostPath(new_path, scratch_new, sizeof(scratch_new), &overflow_new));
}

extern "C" int mocktail_unlink(const char* path) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::unlink(HostPath(path, scratch, sizeof(scratch), &overflow));
}

extern "C" int mocktail_rmdir(const char* path) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::rmdir(HostPath(path, scratch, sizeof(scratch), &overflow));
}

extern "C" char* mocktail_realpath(const char* path, char* resolved_path) {
  char scratch[PATH_MAX];
  std::string overflow;
  const char* host_path = HostPath(path, scratch, sizeof(scratch), &overflow);
  if (resolved_path != nullptr) {
    return ::realpath(host_path, resolved_path);
  }

  char canonical_path[PATH_MAX];
  if (::realpath(host_path, canonical_path) == nullptr) {
    return nullptr;
  }
  const size_t bytes = std::strlen(canonical_path) + 1;
  libc_shim::GuestAllocator allocator = libc_shim::GuestAllocatorForCalls();
  if (allocator == nullptr) {
    return ::strdup(canonical_path);
  }
  auto* result = static_cast<char*>(allocator(bytes));
  if (result == nullptr) {
    errno = ENOMEM;
    return nullptr;
  }
  std::memcpy(result, canonical_path, bytes);
  return result;
}

extern "C" ssize_t mocktail_readlink(const char* path, char* buf,
                                      size_t bufsiz) {
  char scratch[PATH_MAX];
  std::string overflow;
  return ::readlink(HostPath(path, scratch, sizeof(scratch), &overflow), buf,
                    bufsiz);
}

extern "C" ssize_t mocktail___readlink_chk(const char* path, char* buf,
                                            size_t len, size_t buf_len) {
  // Bionic treats impossible ssize_t results and proven overruns as fatal;
  // returning EINVAL would continue after a detected buffer overflow.
  if (len > static_cast<size_t>(SSIZE_MAX)) {
    std::fprintf(stderr,
                 "FORTIFY: readlink: size %zu > SSIZE_MAX\n", len);
    std::abort();
  }
  if (len > buf_len) {
    std::fprintf(stderr,
                 "FORTIFY: readlink: prevented %zu-byte write into "
                 "%zu-byte buffer\n",
                 len, buf_len);
    std::abort();
  }
  return mocktail_readlink(path, buf, len);
}
