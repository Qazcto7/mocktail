#include "mocktail/graphics/texture_override.h"
#include "mocktail/mocktail_rust.h"

#include <png.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>

namespace mocktail::graphics {

std::uint64_t HashBytes(const std::uint8_t* data, std::size_t size) {
  return mocktail_rust_texture_override_hash_bytes(data, size);
}

std::string HashName(std::uint64_t hash) {
  char text[17];
  if (mocktail_rust_texture_override_hash_name(hash, text, sizeof(text)) == 0) {
    return text;
  }
  return {};
}

bool ReadPngRgba(const std::string& path, RgbaImage* image) {
  if (image == nullptr) {
    return false;
  }
  png_image png{};
  png.version = PNG_IMAGE_VERSION;
  if (png_image_begin_read_from_file(&png, path.c_str()) == 0) {
    return false;
  }
  png.format = PNG_FORMAT_RGBA;
  RgbaImage result;
  result.width = png.width;
  result.height = png.height;
  result.pixels.resize(PNG_IMAGE_SIZE(png));
  if (png_image_finish_read(&png, nullptr, result.pixels.data(), 0,
                            nullptr) == 0) {
    png_image_free(&png);
    return false;
  }
  *image = std::move(result);
  return true;
}

bool WritePngRgba(const std::string& path, const RgbaImage& image) {
  if (image.width == 0 || image.height == 0 ||
      image.pixels.size() !=
          static_cast<std::size_t>(image.width) * image.height * 4) {
    return false;
  }
  png_image png{};
  png.version = PNG_IMAGE_VERSION;
  png.width = image.width;
  png.height = image.height;
  png.format = PNG_FORMAT_RGBA;
  const int written = png_image_write_to_file(&png, path.c_str(), 0,
                                              image.pixels.data(), 0, nullptr);
  png_image_free(&png);
  return written != 0;
}

void ResampleRgba(const RgbaImage& source, std::uint32_t width,
                  std::uint32_t height, std::uint8_t* destination) {
  if (source.pixels.size() <
      static_cast<std::size_t>(source.width) * source.height * 4) {
    return;
  }
  ResampleRgba(source.pixels.data(), source.width, source.height, width,
               height, destination);
}

void ResampleRgba(const std::uint8_t* source, std::uint32_t source_width,
                  std::uint32_t source_height, std::uint32_t width,
                  std::uint32_t height, std::uint8_t* destination) {
  mocktail_rust_texture_override_resample_rgba(
      source, source_width, source_height, width, height, destination);
}

namespace {

std::string EnvironmentString(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr ? value : "";
}

bool HasPng(const std::string& dir) {
  return mocktail_rust_texture_override_has_png(dir.c_str()) != 0;
}

}  // namespace

TextureOverrides::TextureOverrides(std::string override_dir,
                                   std::string dump_dir)
    : override_dir_(std::move(override_dir)), dump_dir_(std::move(dump_dir)) {
  if (!override_dir_.empty() && !HasPng(override_dir_)) {
    override_dir_.clear();
  }
}

TextureOverrides TextureOverrides::FromEnvironment() {
  return TextureOverrides(EnvironmentString("MOCKTAIL_TEXTURE_OVERRIDE_DIR"),
                          EnvironmentString("MOCKTAIL_TEXTURE_DUMP_DIR"));
}

std::shared_ptr<const RgbaImage> TextureOverrides::Lookup(std::uint64_t hash) {
  if (override_dir_.empty()) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(mutex_);
  const auto cached = cache_.find(hash);
  if (cached != cache_.end()) {
    return cached->second;
  }
  std::shared_ptr<const RgbaImage> loaded;
  RgbaImage image;
  const std::string path = override_dir_ + "/" + HashName(hash) + ".png";
  if (ReadPngRgba(path, &image) && image.width > 0 && image.height > 0) {
    loaded = std::make_shared<const RgbaImage>(std::move(image));
    std::fprintf(stderr, "  [vulkan] texture override loaded: %s (%ux%u)\n",
                 path.c_str(), loaded->width, loaded->height);
  }
  cache_[hash] = loaded;
  return loaded;
}

void TextureOverrides::Dump(std::uint64_t hash, std::uint32_t width,
                            std::uint32_t height, const std::uint8_t* rgba) {
  if (dump_dir_.empty() || rgba == nullptr || width == 0 || height == 0) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!dumped_.insert(hash).second) {
      return;
    }
  }
  std::error_code error;
  std::filesystem::create_directories(dump_dir_, error);
  RgbaImage image;
  image.width = width;
  image.height = height;
  image.pixels.assign(rgba, rgba + static_cast<std::size_t>(width) * height * 4);
  const std::string path = dump_dir_ + "/" + HashName(hash) + "_" +
                           std::to_string(width) + "x" +
                           std::to_string(height) + ".png";
  if (!WritePngRgba(path, image)) {
    std::fprintf(stderr, "  [vulkan] texture dump failed: %s\n", path.c_str());
  }
}

}  // namespace mocktail::graphics
