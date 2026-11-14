#include "libc_shim/vulkan_etc1_sky_transcoder.h"
#include "mocktail/mocktail_rust.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace libc_shim {
namespace {

constexpr size_t kMaxSkyTextureSize = 16U * 1024U * 1024U;
constexpr size_t kMaxCachedSkyTextures = 16U;
constexpr size_t kMaxCachedSkyBytes = 64U * 1024U * 1024U;

struct SkyTranscodeCacheEntry {
  std::vector<unsigned char> data;
  std::list<std::string>::iterator lru_it;
};

struct SkyTranscodeCache {
  std::mutex mutex;
  std::list<std::string> lru;
  std::unordered_map<std::string, SkyTranscodeCacheEntry> entries;
  size_t total_bytes = 0;

  bool Lookup(const std::string& key, std::vector<unsigned char>* out) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = entries.find(key);
    if (it == entries.end()) {
      return false;
    }
    lru.splice(lru.begin(), lru, it->second.lru_it);
    *out = it->second.data;
    return true;
  }

  void Insert(const std::string& key, const std::vector<unsigned char>& value) {
    if (value.size() > kMaxCachedSkyBytes) {
      return;
    }
    std::lock_guard<std::mutex> lock(mutex);
    auto existing = entries.find(key);
    if (existing != entries.end()) {
      total_bytes -= existing->second.data.size();
      existing->second.data = value;
      total_bytes += existing->second.data.size();
      lru.splice(lru.begin(), lru, existing->second.lru_it);
    } else {
      lru.push_front(key);
      entries.emplace(key, SkyTranscodeCacheEntry{value, lru.begin()});
      total_bytes += value.size();
    }
    while (!lru.empty() &&
           (entries.size() > kMaxCachedSkyTextures ||
            total_bytes > kMaxCachedSkyBytes)) {
      const std::string& oldest_key = lru.back();
      auto erase_it = entries.find(oldest_key);
      if (erase_it != entries.end()) {
        total_bytes -= erase_it->second.data.size();
        entries.erase(erase_it);
      }
      lru.pop_back();
    }
  }
};

SkyTranscodeCache& Cache() {
  static SkyTranscodeCache cache;
  return cache;
}

} // namespace

bool IsBundledSkyTexture(const char *path) {
  return mocktail_rust_etc1_is_bundled_sky_texture(path) != 0;
}

// ETC decoder adapted from AssetStudio's Texture2DDecoderNative (in mocktail-core Rust).
// MIT License. Copyright (c) 2016 Radu and (c) 2016-2020 Perfare.
void ConvertEtc1RgbBlockToBc1(const uint8_t *etc1, uint8_t *bc1) {
  (void)mocktail_rust_etc1_convert_rgb_block_to_bc1(etc1, bc1);
}

bool TranscodeEtc1SkyTextureForVulkan(const char *path,
                                      std::vector<unsigned char> *data) {
  if (!IsBundledSkyTexture(path) || data == nullptr ||
      data->size() > kMaxSkyTextureSize) {
    return false;
  }

  const std::string path_key = path != nullptr ? path : "";
  if (Cache().Lookup(path_key, data)) {
    return true;
  }

  if (mocktail_rust_etc1_transcode_ktx1_for_vulkan(data->data(),
                                                   data->size()) == 0) {
    return false;
  }

  Cache().Insert(path_key, *data);

  std::fprintf(stderr,
               "  [asset] Transcoded bundled ETC1 sky texture to BC1 for "
               "Vulkan: %s\n",
               path);
  return true;
}

} // namespace libc_shim
