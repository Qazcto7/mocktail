#include "runtime/roblox_cookie_store.h"

#include <array>
#include <atomic>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/environment.h"
#include "runtime/runtime_config_file.h"
#include "runtime/runtime_paths.h"

#ifndef MOCKTAIL_INSTALL_LIBDIR
#define MOCKTAIL_INSTALL_LIBDIR "lib"
#endif

namespace mocktail::runtime {
namespace {

std::atomic<void (*)(std::string_view)> warning_handler{nullptr};
std::atomic<bool> warning_shown{false};

void ClearString(std::string* value) {
  if (value == nullptr || value->empty()) return;
  mocktail_rust_secure_zero(value->data(), value->size());
  value->clear();
}

void AssignCallbackString(void* ctx, const char* data, size_t len) {
  auto* target = static_cast<std::string*>(ctx);
  if (target != nullptr && data != nullptr && len > 0) {
    target->assign(data, len);
  }
}

struct ReadCookieContext {
  StoredCookie* result = nullptr;
};

void OnCookieValue(void* ctx, const char* data, size_t len) {
  auto* context = static_cast<ReadCookieContext*>(ctx);
  if (context != nullptr && context->result != nullptr && data != nullptr &&
      len > 0) {
    context->result->value.assign(data, len);
  }
}

void OnCookieError(void* ctx, const char* data, size_t len) {
  auto* context = static_cast<ReadCookieContext*>(ctx);
  if (context != nullptr && context->result != nullptr && data != nullptr &&
      len > 0) {
    context->result->error.assign(data, len);
  }
}

class NotifyingSecretStore : public RobloxSecretStore {
 public:
  void Warn(std::string_view message) override {
    RobloxSecretStore::Warn(message);
    if (warning_shown.exchange(true)) return;
    if (const auto handler = warning_handler.load()) handler(message);
  }
};

class DisabledSecretStore final : public NotifyingSecretStore {
 public:
  bool enabled() const override { return false; }
  StoredCookie Load(const std::filesystem::path&) override { return {}; }
};

std::string ExchangeCookie(char operation, const std::filesystem::path& profile,
                           std::string_view cookie = {}) {
  const std::string profile_str = profile.string();
  const std::string_view libdir = MOCKTAIL_INSTALL_LIBDIR;
  std::string response;
  const int32_t rc = mocktail_rust_cookie_helper_exchange(
      static_cast<uint8_t>(operation), profile_str.data(), profile_str.size(),
      cookie.data(), cookie.size(), libdir.data(), libdir.size(),
      &AssignCallbackString, &response);
  if (rc != 0) {
    ClearString(&response);
  }
  return response;
}

class HelperSecretStore final : public NotifyingSecretStore {
 public:
  StoredCookie Load(const std::filesystem::path& profile) override {
    if (!available_) return RobloxSecretStore::Load(profile);
    std::string response = ExchangeCookie('L', profile);
    StoredCookie result;
    result.from_secret_store = true;
    if (!response.empty() && response.front() == 'F') {
      result.status = StoredCookieStatus::kFound;
      result.value = response.substr(1);
    } else if (response != "M") {
      available_ = false;
      result = RobloxSecretStore::Load(profile);
    }
    ClearString(&response);
    return result;
  }
  bool Store(const std::filesystem::path& profile,
             const std::string& cookie) override {
    if (!available_) return false;
    const bool stored = ExchangeCookie('S', profile, cookie) == "F";
    if (!stored) available_ = false;
    return stored;
  }
  bool Clear(const std::filesystem::path& profile) override {
    return available_ && ExchangeCookie('C', profile) == "F";
  }

 private:
  std::atomic<bool> available_{true};
};

}  // namespace

StoredCookie RobloxSecretStore::Load(const std::filesystem::path&) {
  return {StoredCookieStatus::kUnavailable,
          {},
          "secure Roblox cookie storage is unavailable",
          true};
}

bool RobloxSecretStore::Store(const std::filesystem::path&,
                              const std::string&) {
  return false;
}
bool RobloxSecretStore::Clear(const std::filesystem::path&) { return false; }

void RobloxSecretStore::Warn(std::string_view message) {
  std::fprintf(stderr, "  [auth] %.*s\n", static_cast<int>(message.size()),
               message.data());
}

std::shared_ptr<RobloxSecretStore> OpenRobloxSecretStore() {
  return OpenRobloxSecretStore(ProcessEnvironment());
}

std::shared_ptr<RobloxSecretStore> OpenRobloxSecretStore(
    const Environment& environment) {
  const auto paths = RuntimePaths::FromEnvironment(environment);
  const auto loaded = LoadRuntimeConfig(environment, paths.config_file());
  if (loaded && loaded.config.use_libsecret())
    return std::make_shared<HelperSecretStore>();
  return std::make_shared<DisabledSecretStore>();
}

void SetRobloxCookieWarningHandler(void (*handler)(std::string_view)) {
  warning_handler.store(handler);
}

StoredCookie ReadRobloxCookieFile(const std::filesystem::path& path,
                                  bool required) {
  StoredCookie result;
  const std::string path_str = path.string();
  ReadCookieContext ctx{&result};
  const int32_t status = mocktail_rust_read_roblox_cookie_file(
      path_str.data(), path_str.size(), required ? 1 : 0, &OnCookieValue,
      &OnCookieError, &ctx);
  switch (status) {
    case 0:
      result.status = StoredCookieStatus::kFound;
      break;
    case 1:
      result.status = StoredCookieStatus::kMissing;
      break;
    default:
      result.status = StoredCookieStatus::kUnavailable;
      break;
  }
  return result;
}

StoredCookie LoadManagedRobloxCookie(const std::filesystem::path& path,
                                     RobloxSecretStore& secrets) {
  StoredCookie file = ReadRobloxCookieFile(path);
  return file.status == StoredCookieStatus::kMissing ? secrets.Load(path)
                                                     : std::move(file);
}

bool RemoveLegacyWebViewCookies(const std::filesystem::path& directory) {
  const std::string dir_str = directory.string();
  return mocktail_rust_remove_legacy_webview_cookies(dir_str.data(),
                                                     dir_str.size()) != 0;
}

}  // namespace mocktail::runtime
