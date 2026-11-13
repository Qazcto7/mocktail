#include "libc_shim/vulkan_etc1_sky_transcoder.h"
#include "mocktail/mocktail_rust.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace libc_shim {
namespace {

constexpr size_t kMaxSkyTextureSize = 16U * 1024U * 1024U;

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

  static std::mutex s_cache_mutex;
  static std::unordered_map<std::string, std::vector<unsigned char>> s_cached_transcodes;

  const std::string path_key = path != nullptr ? path : "";
  {
    std::lock_guard<std::mutex> lock(s_cache_mutex);
    auto it = s_cached_transcodes.find(path_key);
    if (it != s_cached_transcodes.end()) {
      *data = it->second;
      return true;
    }
  }

  if (mocktail_rust_etc1_transcode_ktx1_for_vulkan(data->data(),
                                                   data->size()) == 0) {
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(s_cache_mutex);
    s_cached_transcodes[path_key] = *data;
  }

  std::fprintf(stderr,
               "  [asset] Transcoded bundled ETC1 sky texture to BC1 for "
               "Vulkan: %s\n",
               path);
  return true;
}

} // namespace libc_shim
