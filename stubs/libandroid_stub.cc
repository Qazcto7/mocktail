// Android NDK compatibility symbols used by libroblox.so on Linux. Asset calls
// can read from an extracted directory or directly from an APK.
//
// Symbols sourced from Android NDK r28 android/native_activity.h,
// android/asset_manager.h, android/looper.h, android/configuration.h.

#include "libc_shim/vulkan_etc1_sky_transcoder.h"
#include "mocktail/mocktail_rust.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <minizip/unzip.h>
#if defined(MOCKTAIL_MINIZIP_HAS_STREAM_TELL)
#include <minizip/mz_strm.h>
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

// Read-only asset access

struct AAssetManager {};
struct AAsset {
  ~AAsset() {
    if (mapped_data != nullptr && mapped_size > 0) {
      ::munmap(const_cast<unsigned char*>(mapped_data), mapped_size);
    }
  }

  const unsigned char* Bytes() const noexcept {
    return mapped_data != nullptr ? mapped_data : data.data();
  }

  size_t Size() const noexcept {
    return mapped_data != nullptr ? mapped_size : data.size();
  }

  std::string path;
  std::string apk_entry;
  const unsigned char* mapped_data = nullptr;
  size_t mapped_size = 0;
  std::vector<unsigned char> data;
  bool loaded = false;
  bool transcoded = false;
  size_t offset = 0;
};
struct AAssetDir {};

namespace {

AAssetManager g_asset_manager;

const char* GetEnvNonEmpty(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && value[0] != '\0' ? value : nullptr;
}

bool TraceEnabled() {
  static const bool enabled =
      GetEnvNonEmpty("MOCKTAIL_ANDROID_STUB_TRACE") != nullptr ||
      GetEnvNonEmpty("MOCKTAIL_WINDOW_TRACE") != nullptr ||
      GetEnvNonEmpty("MOCKTAIL_FULL_TRACE") != nullptr;
  return enabled;
}

bool AssetTraceEnabled() {
  static const bool enabled =
      GetEnvNonEmpty("MOCKTAIL_ASSET_TRACE") != nullptr ||
      GetEnvNonEmpty("MOCKTAIL_TRACE_ALL") != nullptr ||
      GetEnvNonEmpty("MOCKTAIL_FULL_TRACE") != nullptr;
  return enabled;
}

std::string_view StripAssetUriPrefix(std::string_view path) {
  static constexpr const char* kPrefixes[] = {
      "file:///android_asset/",
      "rbxasset://",
  };
  for (const char* prefix : kPrefixes) {
    const size_t prefix_len = std::strlen(prefix);
    if (path.size() >= prefix_len && path.substr(0, prefix_len) == prefix) {
      return path.substr(prefix_len);
    }
  }
  return path;
}

bool HasUnsafePathSegment(std::string_view path) {
  if (path.empty() || path[0] == '/') {
    return true;
  }
  return path == "." || path == ".." ||
         path.find("/../") != std::string_view::npos || path.find("../") == 0 ||
         (path.size() >= 3 && path.rfind("/..") == path.size() - 3) ||
         path.find("//") != std::string_view::npos;
}

std::string_view StripAndroidAssetPrefix(std::string_view path) {
  static constexpr const char* kPrefixes[] = {
      "assets/",
      "content/",
  };
  for (const char* prefix : kPrefixes) {
    const size_t prefix_len = std::strlen(prefix);
    if (path.size() >= prefix_len && path.substr(0, prefix_len) == prefix) {
      return path.substr(prefix_len);
    }
  }
  return path;
}

bool FileExists(const std::string& path) {
  struct stat st;
  return !path.empty() && ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

struct AssetLookupCache {
  std::mutex mutex;
  std::unordered_map<std::string, std::string> resolved_paths;
};

AssetLookupCache g_asset_lookup_cache;
constexpr std::size_t kMaxCachedAssetPaths = 1024 * 5;
std::once_flag g_register_asset_trim_once;

extern "C" void mocktail_android_trim_asset_cache(int32_t android_trim_level) {
  std::scoped_lock lock(g_asset_lookup_cache.mutex);
  if (android_trim_level >= 15) {
    g_asset_lookup_cache.resolved_paths.clear();
  } else if (android_trim_level >= 10 &&
             g_asset_lookup_cache.resolved_paths.size() > 256) {
    const std::size_t target_keep =
        g_asset_lookup_cache.resolved_paths.size() / 2;
    while (g_asset_lookup_cache.resolved_paths.size() > target_keep) {
      g_asset_lookup_cache.resolved_paths.erase(
          g_asset_lookup_cache.resolved_paths.begin());
    }
  }
}

void RegisterAssetCacheTrimCallback() {
  std::call_once(g_register_asset_trim_once, []() {
    using RegisterFn = int32_t (*)(MocktailRustMemoryTrimFn);
    if (void* sym = dlsym(RTLD_DEFAULT,
                          "mocktail_rust_memory_register_trim_callback")) {
      auto* reg = reinterpret_cast<RegisterFn>(sym);
      (void)reg(&mocktail_android_trim_asset_cache);
    }
  });
}

std::string AssetCacheKey(const std::string& root,
                          const std::string& requested) {
  std::string key;
  key.reserve(root.size() + 1 + requested.size());
  key.append(root);
  key.push_back('\0');
  key.append(requested);
  return key;
}

std::string ResolveAssetPath(const char* filename) {
  RegisterAssetCacheTrimCallback();
  if (filename == nullptr) {
    return {};
  }
  const std::string_view requested_view = StripAssetUriPrefix(filename);
  if (HasUnsafePathSegment(requested_view)) {
    return {};
  }

  const std::string requested(requested_view);
  const char* root_env = GetEnvNonEmpty("MOCKTAIL_ASSET_ROOT");
  const std::string root = root_env != nullptr ? root_env : "rbx_bin/assets";
  const std::string cache_key = AssetCacheKey(root, requested);

  {
    std::scoped_lock lock(g_asset_lookup_cache.mutex);
    auto it = g_asset_lookup_cache.resolved_paths.find(cache_key);
    if (it != g_asset_lookup_cache.resolved_paths.end()) {
      if (FileExists(it->second)) {
        return it->second;
      }
      g_asset_lookup_cache.resolved_paths.erase(it);
    }
  }

  const std::string stripped(StripAndroidAssetPrefix(requested_view));

  const std::vector<std::string> candidates = {
      root + "/" + requested,
      root + "/" + stripped,
      root + "/ExtraContent/" + requested,
      root + "/ExtraContent/" + stripped,
  };
  for (const std::string& candidate : candidates) {
    if (FileExists(candidate)) {
      std::scoped_lock lock(g_asset_lookup_cache.mutex);
      if (g_asset_lookup_cache.resolved_paths.size() >=
              kMaxCachedAssetPaths &&
          g_asset_lookup_cache.resolved_paths.find(cache_key) ==
              g_asset_lookup_cache.resolved_paths.end()) {
        g_asset_lookup_cache.resolved_paths.erase(
            g_asset_lookup_cache.resolved_paths.begin());
      }
      g_asset_lookup_cache.resolved_paths.insert_or_assign(cache_key,
                                                           candidate);
      return candidate;
    }
  }

  return {};
}

bool LoadFile(const std::string& path, std::vector<unsigned char>* data) {
  if (data == nullptr) {
    return false;
  }
  FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return false;
  }
  if (std::fseek(file, 0, SEEK_END) != 0) {
    std::fclose(file);
    return false;
  }
  long size = std::ftell(file);
  if (size < 0) {
    std::fclose(file);
    return false;
  }
  if (std::fseek(file, 0, SEEK_SET) != 0) {
    std::fclose(file);
    return false;
  }
  data->resize(static_cast<size_t>(size));
  if (size > 0) {
    size_t read = std::fread(data->data(), 1, static_cast<size_t>(size), file);
    if (read != static_cast<size_t>(size)) {
      std::fclose(file);
      return false;
    }
  }
  std::fclose(file);
  return true;
}

std::string ApkEntryName(const char* filename) {
  std::string_view requested = StripAssetUriPrefix(filename);
  constexpr const char* kAssetsPrefix = "assets/";
  if (requested.rfind(kAssetsPrefix, 0) == 0) {
    requested.remove_prefix(std::strlen(kAssetsPrefix));
  }
  return "assets/" + std::string(requested);
}

bool OpenStoredApkEntryDescriptor(const std::string& entry_name, int* fd,
                                  off_t* start, off_t* length) {
  const char* apk_path = GetEnvNonEmpty("MOCKTAIL_ASSET_APK_PATH");
  if (apk_path == nullptr || fd == nullptr || start == nullptr ||
      length == nullptr) {
    return false;
  }
  unzFile archive = unzOpen64(apk_path);
  if (archive == nullptr ||
      unzLocateFile(archive, entry_name.c_str(), 1) != UNZ_OK) {
    if (archive != nullptr) {
      unzClose(archive);
    }
    return false;
  }
  unz_file_info64 info{};
  if (unzGetCurrentFileInfo64(archive, &info, nullptr, 0, nullptr, 0, nullptr,
                              0) != UNZ_OK ||
      info.compression_method != 0 || unzOpenCurrentFile(archive) != UNZ_OK) {
    unzClose(archive);
    return false;
  }
  ZPOS64_T data_offset = 0;
#if defined(MOCKTAIL_MINIZIP_HAS_ZSTREAM_POS)
  data_offset = unzGetCurrentFileZStreamPos64(archive);
#elif defined(MOCKTAIL_MINIZIP_HAS_STREAM_TELL)
  const int64_t stream_offset = mz_stream_tell(unzGetStream(archive));
  if (stream_offset < 0) {
    unzCloseCurrentFile(archive);
    unzClose(archive);
    return false;
  }
  data_offset = static_cast<ZPOS64_T>(stream_offset);
#endif
  unzCloseCurrentFile(archive);
  unzClose(archive);
  if (data_offset > static_cast<ZPOS64_T>(INT64_MAX) ||
      info.uncompressed_size > static_cast<ZPOS64_T>(INT64_MAX)) {
    return false;
  }
  const int apk_fd = ::open(apk_path, O_RDONLY | O_CLOEXEC);
  if (apk_fd < 0) {
    return false;
  }
  *fd = apk_fd;
  *start = static_cast<off_t>(data_offset);
  *length = static_cast<off_t>(info.uncompressed_size);
  return true;
}

template <typename Fn>
Fn ResolveCached(Fn* slot, const char* name) {
  Fn fn = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
  if (__builtin_expect(fn == nullptr, 0)) {
    fn = reinterpret_cast<Fn>(dlsym(RTLD_DEFAULT, name));
    if (fn != nullptr) {
      __atomic_store_n(slot, fn, __ATOMIC_RELEASE);
    }
  }
  return fn;
}

void* MocktailNativeWindow() {
  using Fn = void* (*)();
  static Fn cached_fn = nullptr;
  Fn fn = ResolveCached(&cached_fn, "mocktail_native_window");
  return fn != nullptr ? fn() : nullptr;
}

int MocktailWindowWidth() {
  using Fn = int (*)();
  static Fn cached_fn = nullptr;
  Fn fn = ResolveCached(&cached_fn, "mocktail_window_width");
  return fn != nullptr ? fn() : 1280;
}

int MocktailWindowHeight() {
  using Fn = int (*)();
  static Fn cached_fn = nullptr;
  Fn fn = ResolveCached(&cached_fn, "mocktail_window_height");
  return fn != nullptr ? fn() : 720;
}

bool MocktailUsesDirectVulkan() {
  using Fn = bool (*)();
  static Fn cached_fn = nullptr;
  Fn fn = ResolveCached(&cached_fn, "mocktail_window_uses_direct_vulkan");
  if (fn != nullptr) {
    return fn();
  }
  const char* backend = GetEnvNonEmpty("MOCKTAIL_GRAPHICS_BACKEND");
  return backend != nullptr && std::strcmp(backend, "direct-vulkan") == 0;
}

bool EnsureLoaded(AAsset* asset) {
  if (asset->loaded) {
    return true;
  }
  const bool needs_sky_transcode =
      MocktailUsesDirectVulkan() &&
      libc_shim::IsBundledSkyTexture(asset->path.c_str());
  if (!needs_sky_transcode) {
    const int fd = ::open(asset->path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      struct stat st{};
      if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        if (st.st_size == 0) {
          ::close(fd);
          asset->loaded = true;
          return true;
        }
        const size_t size = static_cast<size_t>(st.st_size);
        void* mapped =
            ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        ::close(fd);
        if (mapped != MAP_FAILED) {
          (void)::posix_madvise(mapped, size, POSIX_MADV_SEQUENTIAL);
          asset->mapped_data = static_cast<const unsigned char*>(mapped);
          asset->mapped_size = size;
          asset->loaded = true;
          return true;
        }
      } else {
        ::close(fd);
      }
    }
  }
  if (!LoadFile(asset->path, &asset->data)) {
    asset->data.clear();
    return false;
  }
  asset->loaded = true;
  if (needs_sky_transcode) {
    asset->transcoded = libc_shim::TranscodeEtc1SkyTextureForVulkan(
        asset->path.c_str(), &asset->data);
  }
  return true;
}

}  // namespace

extern "C" {

AAsset* AAssetManager_open(AAssetManager* mgr, const char* filename,
                           int) {
  if (mgr == nullptr) {
    return nullptr;
  }
  std::string path = ResolveAssetPath(filename);
  if (path.empty()) {
    return nullptr;
  }
  auto* asset = new AAsset;
  asset->path = path;
  asset->apk_entry = ApkEntryName(filename);
  if (MocktailUsesDirectVulkan() && libc_shim::IsBundledSkyTexture(path.c_str()) &&
      !EnsureLoaded(asset)) {
    delete asset;
    return nullptr;
  }
  if (AssetTraceEnabled()) {
    std::fprintf(stderr, "[asset] open %s -> %s\n", filename, path.c_str());
  }
  return asset;
}

void AAsset_close(AAsset* asset) {
  if (asset != nullptr && AssetTraceEnabled() &&
      asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] close %s buffer=%p size=%zu\n",
                 asset->path.c_str(), asset->data.data(), asset->data.size());
  }
  delete asset;
}

int AAsset_read(AAsset* asset, void* buf, size_t count) {
  if (asset == nullptr || buf == nullptr || !EnsureLoaded(asset)) {
    return -1;
  }
  const size_t total_size = asset->Size();
  const size_t remaining =
      asset->offset <= total_size ? total_size - asset->offset : 0;
  const size_t to_read = std::min(count, remaining);
  if (to_read > 0) {
    std::memcpy(buf, asset->Bytes() + asset->offset, to_read);
    asset->offset += to_read;
  }
  if (AssetTraceEnabled() && asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] read %s count=%zu -> %zu offset=%zu\n",
                 asset->path.c_str(), count, to_read, asset->offset);
  }
  return static_cast<int>(to_read);
}

const void* AAsset_getBuffer(AAsset* asset) {
  if (asset == nullptr || !EnsureLoaded(asset)) {
    return nullptr;
  }
  const size_t total_size = asset->Size();
  if (AssetTraceEnabled() && asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] getBuffer %s -> %zu bytes\n",
                 asset->path.c_str(), total_size);
  }
  return total_size == 0 ? static_cast<const void*>("")
                         : static_cast<const void*>(asset->Bytes());
}

off_t AAsset_getLength(AAsset* asset) {
  if (asset != nullptr) {
    EnsureLoaded(asset);
  }
  const size_t total_size = asset != nullptr ? asset->Size() : 0;
  if (asset != nullptr && AssetTraceEnabled() &&
      asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] getLength %s -> %zu bytes\n",
                 asset->path.c_str(), total_size);
  }
  return static_cast<off_t>(total_size);
}

off_t AAsset_getLength64(AAsset* asset) { return AAsset_getLength(asset); }

off_t AAsset_getRemainingLength(AAsset* asset) {
  if (asset == nullptr || !EnsureLoaded(asset)) {
    return 0;
  }
  const size_t total_size = asset->Size();
  if (asset->offset > total_size) {
    return 0;
  }
  if (AssetTraceEnabled() && asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] getRemainingLength %s -> %zu bytes\n",
                 asset->path.c_str(), total_size - asset->offset);
  }
  return static_cast<off_t>(total_size - asset->offset);
}

off_t AAsset_getRemainingLength64(AAsset* asset) {
  return AAsset_getRemainingLength(asset);
}

off_t AAsset_seek(AAsset* asset, off_t offset, int whence) {
  if (asset == nullptr || !EnsureLoaded(asset)) {
    return -1;
  }
  const size_t total_size = asset->Size();
  off_t base = 0;
  if (whence == SEEK_SET) {
    base = 0;
  } else if (whence == SEEK_CUR) {
    base = static_cast<off_t>(asset->offset);
  } else if (whence == SEEK_END) {
    base = static_cast<off_t>(total_size);
  } else {
    errno = EINVAL;
    return -1;
  }
  off_t next = base + offset;
  if (next < 0) {
    errno = EINVAL;
    return -1;
  }
  const auto clamped = std::min(static_cast<size_t>(next), total_size);
  asset->offset = clamped;
  if (AssetTraceEnabled() && asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr, "[asset] seek %s offset=%lld whence=%d -> %zu\n",
                 asset->path.c_str(), static_cast<long long>(offset), whence,
                 asset->offset);
  }
  return static_cast<off_t>(asset->offset);
}

off_t AAsset_seek64(AAsset* asset, off_t offset, int whence) {
  return AAsset_seek(asset, offset, whence);
}

int AAsset_openFileDescriptor(AAsset* asset, off_t* outStart,
                              off_t* outLength) {
  if (asset == nullptr || asset->path.empty()) {
    return -1;
  }
  // Force buffered reads: files still contain the original ETC1 bytes.
  if (asset->transcoded) {
    return -1;
  }
  int fd = -1;
  off_t start = 0;
  off_t descriptor_length = static_cast<off_t>(asset->Size());
  if (!OpenStoredApkEntryDescriptor(asset->apk_entry, &fd, &start,
                                    &descriptor_length)) {
    fd = ::open(asset->path.c_str(), O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd >= 0 && !asset->loaded && ::fstat(fd, &st) == 0) {
      descriptor_length = st.st_size;
    }
  }
  if (fd < 0) {
    return -1;
  }
  if (outStart != nullptr) {
    *outStart = start;
  }
  if (outLength != nullptr) {
    *outLength = descriptor_length;
  }
  if (AssetTraceEnabled() && asset->path.find("shader") != std::string::npos) {
    std::fprintf(stderr,
                 "[asset] openFileDescriptor %s -> fd=%d start=%lld "
                 "length=%zu\n",
                 asset->path.c_str(), fd, static_cast<long long>(start),
                 static_cast<size_t>(descriptor_length));
  }
  return fd;
}

int AAsset_openFileDescriptor64(AAsset* asset, off_t* outStart,
                                off_t* outLength) {
  return AAsset_openFileDescriptor(asset, outStart, outLength);
}

AAssetManager* AAssetManager_fromJava(void*, void*) {
  return &g_asset_manager;
}

// AConfiguration — device configuration query

struct AConfiguration {};

AConfiguration* AConfiguration_new() {
  return static_cast<AConfiguration*>(calloc(1, sizeof(AConfiguration)));
}

void AConfiguration_delete(AConfiguration* config) { free(config); }

void AConfiguration_fromAssetManager(AConfiguration*,
                                     AAssetManager*) {}

void AConfiguration_getLanguage(AConfiguration*, char* out) {
  if (out) {
    out[0] = 'e';
    out[1] = 'n';
  }
}

void AConfiguration_getCountry(AConfiguration*, char* out) {
  if (out) {
    out[0] = 'U';
    out[1] = 'S';
  }
}

int32_t AConfiguration_getScreenSize(AConfiguration*) {
  return 2;  // ACONFIGURATION_SCREENSIZE_NORMAL
}

int32_t AConfiguration_getScreenWidthDp(AConfiguration*) {
  return 360;
}

int32_t AConfiguration_getScreenHeightDp(AConfiguration*) {
  return 640;
}

int32_t AConfiguration_getNavHidden(AConfiguration*) {
  return 1;  // ACONFIGURATION_NAVHIDDEN_YES
}

}  // extern "C"

// ALooper — pure-Rust epoll + eventfd event loop (rust/mocktail-core/src/android_looper.rs)

extern "C" {

struct ALooper;

ALooper* ALooper_forThread() {
  return reinterpret_cast<ALooper*>(mocktail_rust_alooper_for_thread());
}

ALooper* ALooper_prepare(int opts) {
  return reinterpret_cast<ALooper*>(mocktail_rust_alooper_prepare(opts));
}

void ALooper_acquire(ALooper* looper) {
  mocktail_rust_alooper_acquire(
      reinterpret_cast<MocktailRustALooper*>(looper));
}

void ALooper_release(ALooper* looper) {
  mocktail_rust_alooper_release(
      reinterpret_cast<MocktailRustALooper*>(looper));
}

int ALooper_addFd(ALooper* looper, int fd, int ident, int events,
                  int (*callback)(int, int, void*), void* data) {
  return mocktail_rust_alooper_add_fd(
      reinterpret_cast<MocktailRustALooper*>(looper), fd, ident, events,
      callback, data);
}

int ALooper_removeFd(ALooper* looper, int fd) {
  return mocktail_rust_alooper_remove_fd(
      reinterpret_cast<MocktailRustALooper*>(looper), fd);
}

void ALooper_wake(ALooper* looper) {
  mocktail_rust_alooper_wake(reinterpret_cast<MocktailRustALooper*>(looper));
}

bool ALooper_isPolling(ALooper* looper) {
  return mocktail_rust_alooper_is_polling(
      reinterpret_cast<MocktailRustALooper*>(looper));
}

int ALooper_pollOnce(int timeout_ms, int* out_fd, int* out_events,
                     void** out_data) {
  return mocktail_rust_alooper_poll_once(timeout_ms, out_fd, out_events,
                                         out_data);
}

int ALooper_pollAll(int timeout_ms, int* out_fd, int* out_events,
                    void** out_data) {
  return mocktail_rust_alooper_poll_all(timeout_ms, out_fd, out_events,
                                        out_data);
}

// ANativeWindow — surface / window handle

struct ANativeWindow {};

void ANativeWindow_acquire(ANativeWindow*) {}
void ANativeWindow_release(ANativeWindow*) {}

ANativeWindow* ANativeWindow_fromSurface(void* env, void* surface) {
  void* native_window = MocktailNativeWindow();
  // The direct-Vulkan WSI adapter ignores the Android window
  // member and creates VkSurfaceKHR from SDL_Window. Preserve the Java Surface
  // token as its opaque ANativeWindow identity so a recreated Surface is not
  // collapsed back onto the same SDL_Window pointer inside Roblox.
  if (surface != nullptr && MocktailUsesDirectVulkan()) {
    if (TraceEnabled()) {
      std::fprintf(stderr,
                   "[androidstub] ANativeWindow_fromSurface env=%p surface=%p "
                   "-> surface_identity=%p backend_window=%p\n",
                   env, surface, surface, native_window);
    }
    return reinterpret_cast<ANativeWindow*>(surface);
  }
  if (native_window != nullptr) {
    if (TraceEnabled()) {
      std::fprintf(stderr,
                   "[androidstub] ANativeWindow_fromSurface env=%p surface=%p "
                   "-> native_window=%p\n",
                   env, surface, native_window);
    }
    return reinterpret_cast<ANativeWindow*>(native_window);
  }
  static ANativeWindow fallback_window;
  if (TraceEnabled()) {
    std::fprintf(stderr,
                 "[androidstub] ANativeWindow_fromSurface env=%p surface=%p "
                 "-> fallback_window=%p\n",
                 env, surface, static_cast<void*>(&fallback_window));
  }
  return &fallback_window;
}

int32_t ANativeWindow_getWidth(ANativeWindow* window) {
  int width = MocktailWindowWidth();
  if (TraceEnabled()) {
    std::fprintf(stderr,
                 "[androidstub] ANativeWindow_getWidth window=%p -> %d\n",
                 static_cast<void*>(window), width);
  }
  return width;
}

int32_t ANativeWindow_getHeight(ANativeWindow* window) {
  int height = MocktailWindowHeight();
  if (TraceEnabled()) {
    std::fprintf(stderr,
                 "[androidstub] ANativeWindow_getHeight window=%p -> %d\n",
                 static_cast<void*>(window), height);
  }
  return height;
}

struct AHardwareBuffer;
void AHardwareBuffer_acquire(AHardwareBuffer* /*buffer*/) {}
void AHardwareBuffer_release(AHardwareBuffer* /*buffer*/) {}

}  // extern "C"
