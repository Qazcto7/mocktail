#include "services/client_settings_service.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "services_rust_bridge.h"

namespace mocktail {
namespace services {
namespace {

using internal::AssignSlice;
using internal::DispatchInjectedHttpGet;
using internal::ToSlice;

ClientSettingsSource SourceFromCode(int32_t code) {
  switch (code) {
    case 0:
      return ClientSettingsSource::kExplicitJson;
    case 1:
      return ClientSettingsSource::kExplicitFile;
    case 2:
      return ClientSettingsSource::kBundledFile;
    case 3:
      return ClientSettingsSource::kSafeDefaults;
    case 4:
      return ClientSettingsSource::kDownloaded;
    case 5:
      return ClientSettingsSource::kCache;
    default:
      return ClientSettingsSource::kEmptyDefaults;
  }
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
    result.error =
        err_buf[0] != '\0' ? err_buf : "failed to load and merge fflags";
    return result;
  }
  result.json = out_buf.data();
  result.count = applied_count;
  result.loaded = (file_loaded != 0);
  return result;
}

ClientSettingsResult ClientSettingsService::Resolve(
    const ClientSettingsOptions& options) {
  const std::string& explicit_file = options.explicit_file.native();
  const std::string& bundled_file = options.bundled_file.native();
  const std::string& cache_file = options.cache_file.native();

  MocktailRustClientSettingsOptionsView ffi_options{};
  ffi_options.explicit_json = ToSlice(options.explicit_json);
  ffi_options.explicit_file = ToSlice(explicit_file);
  ffi_options.bundled_file = ToSlice(bundled_file);
  ffi_options.cache_file = ToSlice(cache_file);
  ffi_options.application = ToSlice(options.application);
  ffi_options.url = ToSlice(options.url);
  ffi_options.use_bundled = options.use_bundled;
  ffi_options.sober_mode = options.sober_mode;
  ffi_options.fetch = options.fetch;
  ffi_options.auto_update = options.auto_update;

  ClientSettingsResult result;
  mocktail_rust_client_settings_resolve(
      &ffi_options, &DispatchInjectedHttpGet, &http_client_,
      [](void* ctx, const MocktailRustClientSettingsResultView* view) {
        auto* out = static_cast<ClientSettingsResult*>(ctx);
        if (out == nullptr || view == nullptr) {
          return;
        }
        out->json = AssignSlice(view->json);
        out->source = SourceFromCode(view->source);
        out->valid_json = view->valid_json;
        out->cache_updated = view->cache_updated;
        out->error = AssignSlice(view->error);
      },
      &result);
  return result;
}

std::string ClientSettingsService::SafeDefaultsJson() {
  char buf[4096] = {};
  if (mocktail_rust_client_settings_safe_defaults(buf, sizeof(buf)) == 0) {
    return std::string(buf);
  }
  return {};
}

std::string ClientSettingsService::DefaultUrl(
    const std::string& application) {
  char buf[1024] = {};
  if (mocktail_rust_client_settings_build_url(application.c_str(), buf,
                                              sizeof(buf)) == 0) {
    return std::string(buf);
  }
  return {};
}

bool ClientSettingsService::IsValidJson(const std::string& content) {
  return mocktail_rust_client_settings_is_valid_json(content.c_str()) == 1;
}

const char* ClientSettingsSourceName(ClientSettingsSource source) {
  return mocktail_rust_client_settings_source_name_ptr(
      static_cast<int32_t>(source));
}

}  // namespace services
}  // namespace mocktail
