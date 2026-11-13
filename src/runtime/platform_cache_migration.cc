#include "runtime/platform_cache_migration.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "runtime/environment.h"
#include "runtime/runtime_paths.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr std::uintmax_t kMaximumJsonBytes = 16U * 1024U * 1024U;
constexpr int kFingerprintSchemaVersion = 1;
constexpr std::string_view kAndroidDataPrefix =
    "/data/user/0/com.roblox.client";
constexpr std::string_view kLegacyAndroidDataPrefix =
    "/data/data/com.roblox.client";
std::atomic<std::uint64_t> g_temporary_sequence{0};

class ScopedFileDescriptor final {
 public:
  explicit ScopedFileDescriptor(int descriptor = -1)
      : descriptor_(descriptor) {}
  ~ScopedFileDescriptor() {
    if (descriptor_ >= 0) {
      close(descriptor_);
    }
  }

  ScopedFileDescriptor(const ScopedFileDescriptor&) = delete;
  ScopedFileDescriptor& operator=(const ScopedFileDescriptor&) = delete;

  int get() const { return descriptor_; }

 private:
  int descriptor_ = -1;
};

enum class ReadStatus { kMissing, kReady, kInvalid };

struct JsonReadResult {
  ReadStatus status = ReadStatus::kMissing;
  std::string value;
  std::string error;
};

bool HasPathPrefix(const std::filesystem::path& path,
                   const std::filesystem::path& prefix) {
  return mocktail_rust_has_path_prefix(path.c_str(), prefix.c_str()) == 1;
}

std::optional<std::filesystem::path> TranslateAndroidFilesPath(
    std::string_view configured, const std::filesystem::path& data_root) {
  std::string conf_str(configured);
  char out_buf[4096];
  if (mocktail_rust_translate_android_files_path(
          conf_str.c_str(), data_root.c_str(), out_buf, sizeof(out_buf)) == 0) {
    return std::filesystem::path(out_buf);
  }
  return std::nullopt;
}

bool WriteAll(int descriptor, std::string_view bytes) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t written =
        write(descriptor, bytes.data() + offset, bytes.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (written == 0) {
      return false;
    }
    offset += static_cast<std::size_t>(written);
  }
  return true;
}

JsonReadResult ReadJson(const std::filesystem::path& path) {
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    if (errno == ENOENT) {
      return {};
    }
    return {
        ReadStatus::kInvalid, {}, "cannot safely open platform cache metadata"};
  }
  const ScopedFileDescriptor file(descriptor);
  struct stat status{};
  if (fstat(file.get(), &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_size < 0 ||
      static_cast<std::uintmax_t>(status.st_size) > kMaximumJsonBytes) {
    return {ReadStatus::kInvalid,
            {},
            "platform cache metadata is not a bounded regular file"};
  }

  std::string bytes(static_cast<std::size_t>(status.st_size), '\0');
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count =
        read(file.get(), bytes.data() + offset, bytes.size() - offset);
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      return {ReadStatus::kInvalid, {}, "cannot read platform cache metadata"};
    }
    if (count == 0) {
      return {ReadStatus::kInvalid,
              {},
              "platform cache metadata changed while being read"};
    }
    offset += static_cast<std::size_t>(count);
  }
  const bool valid = mocktail_rust_json_normalize_object(
                         bytes.data(), bytes.size(), true, nullptr, nullptr) == 0;
  if (!valid) {
    std::fill(bytes.begin(), bytes.end(), '\0');
    return {ReadStatus::kInvalid,
            {},
            "platform cache metadata is not a JSON object"};
  }
  return {ReadStatus::kReady, std::move(bytes), {}};
}

bool AtomicWriteBytes(const std::filesystem::path& path,
                      std::string_view bytes, std::string* error) {
  std::error_code filesystem_error;
  if (!RuntimePaths::EnsureDirectory(path.parent_path(), &filesystem_error)) {
    *error = "cannot create platform cache metadata directory";
    return false;
  }
  const std::filesystem::file_status target_status =
      std::filesystem::symlink_status(path, filesystem_error);
  if (!filesystem_error && std::filesystem::is_symlink(target_status)) {
    *error = "platform cache metadata target is a symlink";
    return false;
  }
  if (filesystem_error != std::errc::no_such_file_or_directory &&
      filesystem_error) {
    *error = "cannot inspect platform cache metadata target";
    return false;
  }

  const std::filesystem::path temporary =
      path.parent_path() /
      (".mocktail-platform-cache.tmp." + std::to_string(getpid()) + "." +
       std::to_string(g_temporary_sequence.fetch_add(1)));
  const int descriptor =
      open(temporary.c_str(),
           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    *error = "cannot create temporary platform cache metadata";
    return false;
  }
  bool stored = false;
  {
    const ScopedFileDescriptor file(descriptor);
    stored = fchmod(file.get(), S_IRUSR | S_IWUSR) == 0 &&
             WriteAll(file.get(), bytes) && fsync(file.get()) == 0;
  }
  if (!stored || rename(temporary.c_str(), path.c_str()) != 0) {
    const int saved_errno = errno;
    (void)unlink(temporary.c_str());
    errno = saved_errno;
    *error = "cannot atomically store platform cache metadata";
    return false;
  }
  const int directory_descriptor =
      open(path.parent_path().c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
  if (directory_descriptor < 0) {
    *error = "cannot open platform cache metadata directory for sync";
    return false;
  }
  const ScopedFileDescriptor directory(directory_descriptor);
  if (fsync(directory.get()) != 0) {
    *error = "cannot sync platform cache metadata directory";
    return false;
  }
  return true;
}

std::string FingerprintRevision(std::string_view json_str) {
  char rev_buf[128];
  if (mocktail_rust_validate_platform_cache_fingerprint(
          json_str.data(), json_str.size(), rev_buf, sizeof(rev_buf)) == 0) {
    return std::string(rev_buf);
  }
  return {};
}

void ZeroAndClear(std::string* value) {
  std::fill(value->begin(), value->end(), '\0');
  value->clear();
}

}  // namespace

std::string BuildPlatformProfileRevision(std::string_view device_profile,
                                         bool touch_enabled, bool mouse_enabled,
                                         bool keyboard_enabled) {
  const std::string dev_str(device_profile);
  char out_buf[128];
  if (mocktail_rust_build_platform_profile_revision(
          dev_str.c_str(), touch_enabled ? 1 : 0, mouse_enabled ? 1 : 0,
          keyboard_enabled ? 1 : 0, out_buf, sizeof(out_buf)) == 0) {
    return std::string(out_buf);
  }
  return {};
}

PlatformCacheMigrationResult MigratePlatformProfileCaches(
    const Environment& environment, const RuntimePaths& paths,
    std::string_view desired_revision) {
  PlatformCacheMigrationResult result;
  if (desired_revision.empty() || desired_revision.size() > 64) {
    result.error = "platform profile revision is invalid";
    return result;
  }

  const std::filesystem::path runtime_root =
      environment.HasNonEmpty("MOCKTAIL_RUNTIME_ROOT")
          ? std::filesystem::path(
                environment.GetOr("MOCKTAIL_RUNTIME_ROOT", ""))
          : paths.android_runtime_root();
  const std::filesystem::path data_root = runtime_root / "data";
  std::filesystem::path files_root = data_root / "files";
  if (environment.HasNonEmpty("MOCKTAIL_ANDROID_FILES_DIR")) {
    const std::optional<std::filesystem::path> translated =
        TranslateAndroidFilesPath(
            environment.GetOr("MOCKTAIL_ANDROID_FILES_DIR", ""), data_root);
    if (!translated.has_value()) {
      result.error = "configured Android files directory is not absolute";
      return result;
    }
    files_root = *translated;
  }

  const std::filesystem::path normalized_data = data_root.lexically_normal();
  const std::filesystem::path normalized_files = files_root.lexically_normal();
  if (!normalized_data.is_absolute() || !normalized_files.is_absolute() ||
      !HasPathPrefix(normalized_files, normalized_data)) {
    result.error = "platform cache path escapes the Mocktail Android data root";
    return result;
  }

  result.app_storage_file =
      normalized_files / "appData/LocalStorage/appStorage.json";
  result.fingerprint_file = normalized_data / ".mocktail-platform-profile.json";
  std::error_code filesystem_error;
  if (!RuntimePaths::EnsureDirectory(normalized_data, &filesystem_error)) {
    result.error = "cannot create Mocktail Android data root";
    return result;
  }

  const std::filesystem::path lock_path =
      normalized_data / ".mocktail-platform-profile.lock";
  const int lock_descriptor =
      open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lock_descriptor < 0) {
    result.error = "cannot open platform cache migration lock";
    return result;
  }
  const ScopedFileDescriptor lock(lock_descriptor);
  struct stat lock_status = {};
  if (fstat(lock.get(), &lock_status) != 0 || !S_ISREG(lock_status.st_mode) ||
      lock_status.st_uid != geteuid() || lock_status.st_nlink != 1 ||
      (lock_status.st_mode & (S_IRWXG | S_IRWXO)) != 0 ||
      flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
    result.error = "another process owns the platform cache migration lock";
    return result;
  }

  const JsonReadResult fingerprint = ReadJson(result.fingerprint_file);
  if (fingerprint.status == ReadStatus::kInvalid) {
    result.error = fingerprint.error;
    return result;
  }
  if (fingerprint.status == ReadStatus::kReady) {
    result.previous_revision = FingerprintRevision(fingerprint.value);
  }
  if (result.previous_revision == desired_revision) {
    return result;
  }
  result.transitioned = true;

  JsonReadResult app_storage = ReadJson(result.app_storage_file);
  if (app_storage.status == ReadStatus::kInvalid) {
    result.error = app_storage.error;
    return result;
  }
  if (app_storage.status == ReadStatus::kReady) {
    result.app_storage_found = true;
    bool removed = false;
    std::string updated_storage;
    const int32_t rc = mocktail_rust_platform_cache_strip_hydration_keys(
        app_storage.value.data(), app_storage.value.size(), &removed,
        [](void* ctx, const char* ptr, std::size_t len) {
          static_cast<std::string*>(ctx)->assign(ptr, len);
        },
        &updated_storage);
    ZeroAndClear(&app_storage.value);
    if (rc == 0 && removed) {
      const bool wrote = AtomicWriteBytes(result.app_storage_file,
                                          updated_storage, &result.error);
      ZeroAndClear(&updated_storage);
      if (!wrote) {
        return result;
      }
      result.app_storage_updated = true;
    } else {
      ZeroAndClear(&updated_storage);
    }
  }

  std::string updated_fingerprint;
  mocktail_rust_platform_cache_build_fingerprint(
      kFingerprintSchemaVersion, desired_revision.data(),
      desired_revision.size(),
      [](void* ctx, const char* ptr, std::size_t len) {
        static_cast<std::string*>(ctx)->assign(ptr, len);
      },
      &updated_fingerprint);
  if (!AtomicWriteBytes(result.fingerprint_file, updated_fingerprint,
                        &result.error)) {
    return result;
  }
  return result;
}

RobloxThemeCacheResult ReadRobloxThemeCache(
    const std::filesystem::path& app_storage_file,
    std::int64_t authenticated_user_id) {
  RobloxThemeCacheResult result;
  if (!app_storage_file.is_absolute() || authenticated_user_id < -1) {
    result.error = "Roblox theme cache path or user ID is invalid";
    return result;
  }

  JsonReadResult storage = ReadJson(app_storage_file);
  if (storage.status == ReadStatus::kInvalid) {
    result.error = storage.error;
    return result;
  }
  if (storage.status == ReadStatus::kMissing) {
    return result;
  }

  bool has_theme = false;
  bool dark_theme = false;
  mocktail_rust_platform_cache_read_theme(
      storage.value.data(), storage.value.size(), authenticated_user_id,
      &has_theme, &dark_theme);
  ZeroAndClear(&storage.value);
  if (has_theme) {
    result.dark_theme = dark_theme;
  }
  return result;
}

bool ApplyRobloxThemeCacheOverride(
    const std::filesystem::path& app_storage_file,
    std::int64_t authenticated_user_id, bool dark_theme, std::string* error) {
  if (error == nullptr || !app_storage_file.is_absolute() ||
      authenticated_user_id < -1) {
    if (error != nullptr) {
      *error = "Roblox theme cache path or user ID is invalid";
    }
    return false;
  }

  JsonReadResult storage = ReadJson(app_storage_file);
  if (storage.status == ReadStatus::kInvalid) {
    *error = storage.error;
    return false;
  }
  const bool has_storage = (storage.status == ReadStatus::kReady);
  bool changed = false;
  std::string updated_storage;
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_platform_cache_apply_theme(
      storage.value.data(), storage.value.size(), has_storage,
      authenticated_user_id, dark_theme, &changed,
      [](void* ctx, const char* ptr, std::size_t len) {
        static_cast<std::string*>(ctx)->assign(ptr, len);
      },
      &updated_storage, err_buf.data(), err_buf.size());
  ZeroAndClear(&storage.value);
  if (rc != 0) {
    ZeroAndClear(&updated_storage);
    *error = err_buf[0] != '\0' ? std::string(err_buf.data())
                                : "platform cache metadata update failed";
    return false;
  }
  if (!changed) {
    ZeroAndClear(&updated_storage);
    return true;
  }
  const bool wrote = AtomicWriteBytes(app_storage_file, updated_storage, error);
  ZeroAndClear(&updated_storage);
  return wrote;
}

}  // namespace runtime
}  // namespace mocktail
