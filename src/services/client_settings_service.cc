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
  char err_buf[512] = {};
  const int rc = mocktail_rust_atomic_write_file(
      path.c_str(), content.data(), content.size(), err_buf, sizeof(err_buf));
  if (rc != 0) {
    if (error_message != nullptr) {
      *error_message = err_buf[0] != '\0' ? err_buf : "could not commit client settings cache";
    }
    return false;
  }
  return true;
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
  char buf[4096] = {};
  if (mocktail_rust_client_settings_safe_defaults(buf, sizeof(buf)) == 0) {
    return std::string(buf);
  }
  return R"json({"applicationSettings":{}})json";
}

std::string ClientSettingsService::DefaultUrl(const std::string& application) {
  char buf[512] = {};
  if (mocktail_rust_client_settings_build_url(application.c_str(), buf, sizeof(buf)) == 0) {
    return std::string(buf);
  }
  return "https://clientsettingscdn.roblox.com/v2/settings/application/" + application;
}

bool ClientSettingsService::IsValidJson(const std::string& content) {
  return mocktail_rust_client_settings_is_valid_json(content.c_str()) == 1;
}

const char* ClientSettingsSourceName(ClientSettingsSource source) {
  thread_local char buf[32];
  mocktail_rust_client_settings_source_name(
      static_cast<int32_t>(source), buf, sizeof(buf));
  return buf;
}

}  // namespace services
}  // namespace mocktail
