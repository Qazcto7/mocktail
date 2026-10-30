#include "services/client_settings_service.h"
#include "mocktail/mocktail_rust.h"

#define JSON_NOEXCEPTION 1
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <system_error>
#include <utility>

#include "runtime/runtime_paths.h"

namespace mocktail {
namespace services {
namespace {

constexpr const char kEmptyDefaults[] = "{\"applicationSettings\":{}}";



std::string ReadFile(const std::filesystem::path& path) {
  if (path.empty()) {
    return {};
  }
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return {};
  }
  return std::string((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
}

bool AtomicWriteFile(const std::filesystem::path& path,
                     const std::string& content, std::string* error_message) {
  if (path.empty()) {
    if (error_message != nullptr) {
      *error_message = "client settings cache path is empty";
    }
    return false;
  }
  std::error_code directory_error;
  const std::filesystem::path parent = path.parent_path().empty()
                                           ? std::filesystem::path(".")
                                           : path.parent_path();
  if (!mocktail::runtime::RuntimePaths::EnsureDirectory(parent,
                                                        &directory_error)) {
    if (error_message != nullptr) {
      *error_message = "could not create client settings cache directory: " +
                       directory_error.message();
    }
    return false;
  }

  const std::filesystem::path temporary =
      path.string() + ".tmp." + std::to_string(getpid());
  const int fd = open(temporary.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (fd < 0) {
    if (error_message != nullptr) {
      *error_message = "could not create client settings temporary file";
    }
    return false;
  }

  bool ok = true;
  const char* cursor = content.data();
  size_t remaining = content.size();
  while (remaining != 0) {
    const ssize_t written = write(fd, cursor, remaining);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      ok = false;
      break;
    }
    cursor += written;
    remaining -= static_cast<size_t>(written);
  }
  if (ok && fsync(fd) != 0) {
    ok = false;
  }
  if (close(fd) != 0) {
    ok = false;
  }
  if (ok && rename(temporary.c_str(), path.c_str()) != 0) {
    ok = false;
  }
  if (!ok) {
    unlink(temporary.c_str());
    if (error_message != nullptr) {
      *error_message = "could not commit client settings cache";
    }
  }
  return ok;
}

ClientSettingsResult FileResult(const std::filesystem::path& path,
                                ClientSettingsSource source) {
  ClientSettingsResult result;
  result.json = ReadFile(path);
  result.source = source;
  result.valid_json = ClientSettingsService::IsValidJson(result.json);
  return result;
}

}  // namespace

FflagsMergeResult LoadAndMergeFflagsFile(const std::filesystem::path& path,
                                         std::string_view base_json) {
  FflagsMergeResult result;
  std::string base_str(base_json.empty() ? "{}" : base_json);
  std::vector<char> out_buf(1024 * 1024);
  size_t applied_count = 0;
  int file_loaded = 0;
  char err_buf[512] = {};
  const char* path_ptr = path.empty() ? nullptr : path.c_str();

  int rc = mocktail_rust_fflags_load_and_merge(
      path_ptr, base_str.c_str(), out_buf.data(), out_buf.size(),
      &applied_count, &file_loaded, err_buf, sizeof(err_buf));
  if (rc == -5) {
    out_buf.resize(8 * 1024 * 1024);
    rc = mocktail_rust_fflags_load_and_merge(
        path_ptr, base_str.c_str(), out_buf.data(), out_buf.size(),
        &applied_count, &file_loaded, err_buf, sizeof(err_buf));
  }
  if (rc != 0) {
    result.json = std::string(base_json);
    result.error = err_buf[0] != '\0' ? err_buf : "failed to load and merge fflags";
    return result;
  }
  result.json = out_buf.data();
  result.count = applied_count;
  result.loaded = (file_loaded != 0);
  return result;
}

ClientSettingsResult ClientSettingsService::Resolve(
    const ClientSettingsOptions& options) {
  if (!options.explicit_json.empty()) {
    return {options.explicit_json,
            ClientSettingsSource::kExplicitJson,
            IsValidJson(options.explicit_json),
            false,
            {}};
  }

  if (!options.explicit_file.empty()) {
    ClientSettingsResult result =
        FileResult(options.explicit_file, ClientSettingsSource::kExplicitFile);
    if (!result.json.empty()) {
      return result;
    }
  }

  if (!options.fetch && options.use_bundled) {
    ClientSettingsResult result =
        FileResult(options.bundled_file, ClientSettingsSource::kBundledFile);
    if (!result.json.empty()) {
      return result;
    }
  }

  if (options.sober_mode && !options.fetch) {
    const std::string defaults = SafeDefaultsJson();
    return {defaults, ClientSettingsSource::kSafeDefaults, true, false, {}};
  }

  std::string update_error;
  if (options.auto_update && !options.cache_file.empty()) {
    HttpRequest request;
    request.url =
        options.url.empty() ? DefaultUrl(options.application) : options.url;
    request.timeout_ms = 20000;
    request.maximum_body_bytes = 16 * 1024 * 1024;
    request.headers.push_back("Accept: application/json");
    HttpResponse response = http_client_.Get(request);
    if (response.transport_ok && response.status_code >= 200 &&
        response.status_code < 300 && !response.body.empty() &&
        IsValidJson(response.body)) {
      const std::string cached = ReadFile(options.cache_file);
      bool updated = false;
      if (cached != response.body) {
        updated =
            AtomicWriteFile(options.cache_file, response.body, &update_error);
      }
      if (cached == response.body || updated) {
        return {response.body, ClientSettingsSource::kDownloaded, true, updated,
                update_error};
      }
    } else if (!response.transport_ok) {
      update_error = std::move(response.error);
    } else if (response.status_code < 200 || response.status_code >= 300) {
      update_error = "client settings server returned HTTP " +
                     std::to_string(response.status_code);
    } else {
      update_error = "client settings response was empty or invalid JSON";
    }
  }

  ClientSettingsResult cached =
      FileResult(options.cache_file, ClientSettingsSource::kCache);
  if (!cached.json.empty()) {
    cached.error = std::move(update_error);
    return cached;
  }

  return {kEmptyDefaults, ClientSettingsSource::kEmptyDefaults, true, false,
          std::move(update_error)};
}

std::string ClientSettingsService::SafeDefaultsJson() {
  return R"json({
    "applicationSettings": {
      "BeginScheduledFlagFetch3": "False",
      "BeginScheduledFlagFetch5": "false",
      "RetryFlagPrefetchOnBackgroundFailure": "false",
      "FFlagEnableVersionCheckFromClientSettingsCDN": "False",
      "FIntScheduledFlagFetchPeriodMinutes": "1000000",
      "FIntScheduledFlagFetchPeriodFlexMinutes": "0",
      "DFFlagFetchAndWriteFlagsAfterSuccessfulCachedFlagsLoad": "False",
      "DFFlagWriteFlagCacheAfterDynamicFetch": "False",
      "DFFlagWriteFlagCacheAfterFlagFetch": "False",
      "DFFlagWriteFlagCacheAfterFlagFetch2": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnStartup3": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnFlagReload3": "False",
      "DFFlagEnableAppPlatformQoSEmergencyOnFlagReload4": "False",
      "FFlagAndroidEnableQoS": "False",
      "FFlagEnableNetworkStatusObserving": "False",
      "DFFlagDontReportAccumulatedStatsInHttpClientDestroy2": "True",
      "FFlagEnableJNIAppbridgeStartMilestone": "False"
    }
  })json";
}

std::string ClientSettingsService::DefaultUrl(const std::string& application) {
  return "https://clientsettingscdn.roblox.com/v2/settings/application/" +
         application;
}

bool ClientSettingsService::IsValidJson(const std::string& content) {
  if (content.empty()) {
    return false;
  }
  const nlohmann::json value =
      nlohmann::json::parse(content, nullptr, false, true);
  return !value.is_discarded() && value.is_object();
}

const char* ClientSettingsSourceName(ClientSettingsSource source) {
  switch (source) {
    case ClientSettingsSource::kExplicitJson:
      return "explicit JSON";
    case ClientSettingsSource::kExplicitFile:
      return "explicit file";
    case ClientSettingsSource::kBundledFile:
      return "bundled file";
    case ClientSettingsSource::kSafeDefaults:
      return "safe defaults";
    case ClientSettingsSource::kDownloaded:
      return "download";
    case ClientSettingsSource::kCache:
      return "cache";
    case ClientSettingsSource::kEmptyDefaults:
      return "empty defaults";
  }
  return "unknown";
}

}  // namespace services
}  // namespace mocktail
